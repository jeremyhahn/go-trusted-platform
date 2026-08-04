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

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// ============================================================================
// Environment Constants
// ============================================================================

const (
	// EnvGRPCEndpoint is the environment variable for the gRPC endpoint.
	EnvGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"

	// DefaultGRPCEndpoint is the default gRPC endpoint.
	DefaultGRPCEndpoint = "localhost:10443"
)

// ============================================================================
// Error Types
// ============================================================================

// ErrGRPCConnection represents a gRPC connection error.
type ErrGRPCConnection struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCConnection) Error() string {
	return fmt.Sprintf("gRPC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnection) Unwrap() error {
	return e.Err
}

// ErrGRPCCall represents a gRPC method call error.
type ErrGRPCCall struct {
	Method string
	Err    error
}

func (e ErrGRPCCall) Error() string {
	return fmt.Sprintf("gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCall) Unwrap() error {
	return e.Err
}

// ErrGRPCStream represents a gRPC streaming error.
type ErrGRPCStream struct {
	Operation string
	Err       error
}

func (e ErrGRPCStream) Error() string {
	return fmt.Sprintf("gRPC stream %s failed: %v", e.Operation, e.Err)
}

func (e ErrGRPCStream) Unwrap() error {
	return e.Err
}

// ErrGRPCValidationFailed represents a gRPC validation failure returned
// as a successful response with Valid=false.
type ErrGRPCValidationFailed struct {
	Errors []string
}

func (e ErrGRPCValidationFailed) Error() string {
	if len(e.Errors) > 0 {
		return fmt.Sprintf("bundle validation failed: %s", e.Errors[0])
	}
	return "bundle validation failed"
}

// ============================================================================
// GRPCAdapter Implementation
// ============================================================================

// GRPCAdapter implements VTPMCommands using gRPC calls to VTPMService.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   platformv1.VTPMServiceClient
}

// NewGRPCAdapter creates a new gRPC adapter instance.
func NewGRPCAdapter() *GRPCAdapter {
	endpoint := os.Getenv(EnvGRPCEndpoint)
	if endpoint == "" {
		endpoint = DefaultGRPCEndpoint
	}
	return &GRPCAdapter{
		endpoint: endpoint,
	}
}

// Name returns the adapter identifier.
func (a *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection and verifies connectivity.
func (a *GRPCAdapter) Setup(ctx context.Context) error {
	conn, err := grpc.NewClient(
		a.endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrGRPCConnection{Endpoint: a.endpoint, Err: err}
	}

	a.conn = conn
	a.client = platformv1.NewVTPMServiceClient(conn)

	// Verify connectivity using the parent context timeout rather than
	// an aggressive short timeout that can cause broken pipe errors
	// when the server is slow to respond during startup.
	_, err = a.client.ListBundles(ctx, &platformv1.ListBundlesRequest{})
	if err != nil {
		a.conn.Close()
		a.conn = nil
		a.client = nil
		return ErrGRPCConnection{Endpoint: a.endpoint, Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (a *GRPCAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// ============================================================================
// Bundle CRUD Operations
// ============================================================================

// CreateBundle creates a new vTPM bundle via gRPC.
func (a *GRPCAdapter) CreateBundle(
	ctx context.Context,
	opts CreateBundleOptions,
) (*CreateBundleResult, error) {
	req := &platformv1.CreateBundleRequest{
		Options: &platformv1.CreateBundleOptions{
			Mode:              bundleModeToProto(opts.Mode),
			Hostname:          opts.Hostname,
			EkAlgorithm:       ekAlgorithmToProto(opts.EKAlgorithm),
			SecureBootEnabled: opts.SecureBootEnabled,
			Labels:            opts.Labels,
			TemplateId:        opts.TemplateID,
		},
	}

	resp, err := a.client.CreateBundle(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "CreateBundle", Err: err}
	}

	return &CreateBundleResult{
		Bundle: protoToBundle(resp.GetBundle()),
	}, nil
}

// GetBundle retrieves a bundle by ID via gRPC.
func (a *GRPCAdapter) GetBundle(
	ctx context.Context,
	opts GetBundleOptions,
) (*GetBundleResult, error) {
	req := &platformv1.GetBundleRequest{
		Id: opts.ID,
	}

	resp, err := a.client.GetBundle(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "GetBundle", Err: err}
	}

	return &GetBundleResult{
		Bundle: protoToBundle(resp.GetBundle()),
	}, nil
}

// DeleteBundle removes a bundle via gRPC.
func (a *GRPCAdapter) DeleteBundle(
	ctx context.Context,
	opts DeleteBundleOptions,
) (*DeleteBundleResult, error) {
	req := &platformv1.DeleteBundleRequest{
		Id: opts.ID,
	}

	resp, err := a.client.DeleteBundle(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "DeleteBundle", Err: err}
	}

	return &DeleteBundleResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListBundles lists bundles with optional filtering via gRPC.
func (a *GRPCAdapter) ListBundles(
	ctx context.Context,
	opts ListBundlesOptions,
) (*ListBundlesResult, error) {
	req := &platformv1.ListBundlesRequest{
		Options: &platformv1.ListBundleOptions{
			Mode:   bundleModeToProto(opts.Mode),
			Labels: opts.Labels,
			Limit:  int32(opts.Limit),
			Offset: int32(opts.Offset),
		},
	}

	resp, err := a.client.ListBundles(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "ListBundles", Err: err}
	}

	bundles := make([]*vtpm.Bundle, 0, len(resp.GetBundles()))
	for _, pb := range resp.GetBundles() {
		bundles = append(bundles, protoToBundle(pb))
	}

	return &ListBundlesResult{
		Bundles: bundles,
		Total:   int(resp.GetTotal()),
	}, nil
}

// ============================================================================
// Template CRUD Operations
// ============================================================================

// CreateTemplate creates a new vTPM template via gRPC.
func (a *GRPCAdapter) CreateTemplate(
	ctx context.Context,
	opts CreateTemplateOptions,
) (*CreateTemplateResult, error) {
	req := &platformv1.CreateTemplateRequest{
		Options: &platformv1.CreateTemplateOptions{
			Id:                opts.ID,
			Description:       opts.Description,
			EkAlgorithm:       ekAlgorithmToProto(opts.EKAlgorithm),
			SecureBootEnabled: opts.SecureBootEnabled,
		},
	}

	resp, err := a.client.CreateTemplate(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "CreateTemplate", Err: err}
	}

	return &CreateTemplateResult{
		Template: protoToTemplate(resp.GetTemplate()),
	}, nil
}

// GetTemplate retrieves a template by ID via gRPC.
func (a *GRPCAdapter) GetTemplate(
	ctx context.Context,
	opts GetTemplateOptions,
) (*GetTemplateResult, error) {
	req := &platformv1.GetTemplateRequest{
		Id: opts.ID,
	}

	resp, err := a.client.GetTemplate(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "GetTemplate", Err: err}
	}

	return &GetTemplateResult{
		Template: protoToTemplate(resp.GetTemplate()),
	}, nil
}

// DeleteTemplate removes a template via gRPC.
func (a *GRPCAdapter) DeleteTemplate(
	ctx context.Context,
	opts DeleteTemplateOptions,
) (*DeleteTemplateResult, error) {
	req := &platformv1.DeleteTemplateRequest{
		Id: opts.ID,
	}

	resp, err := a.client.DeleteTemplate(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "DeleteTemplate", Err: err}
	}

	return &DeleteTemplateResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListTemplates lists all templates via gRPC.
func (a *GRPCAdapter) ListTemplates(
	ctx context.Context,
	opts ListTemplatesOptions,
) (*ListTemplatesResult, error) {
	req := &platformv1.ListTemplatesRequest{}

	resp, err := a.client.ListTemplates(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "ListTemplates", Err: err}
	}

	templates := make([]*vtpm.Template, 0, len(resp.GetTemplates()))
	for _, pt := range resp.GetTemplates() {
		templates = append(templates, protoToTemplate(pt))
	}

	return &ListTemplatesResult{
		Templates: templates,
		Total:     len(templates),
	}, nil
}

// CloneTemplate clones a template to create a new bundle via gRPC.
func (a *GRPCAdapter) CloneTemplate(
	ctx context.Context,
	opts CloneTemplateOptions,
) (*CloneTemplateResult, error) {
	req := &platformv1.CloneTemplateRequest{
		Options: &platformv1.CloneOptions{
			TemplateId: opts.TemplateID,
			Hostname:   opts.Hostname,
			Labels:     opts.Labels,
		},
	}

	resp, err := a.client.CloneTemplate(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "CloneTemplate", Err: err}
	}

	return &CloneTemplateResult{
		Bundle: protoToBundle(resp.GetBundle()),
	}, nil
}

// ============================================================================
// Export/Import Operations
// ============================================================================

// ExportBundle exports a bundle to a tar.gz archive via gRPC streaming.
func (a *GRPCAdapter) ExportBundle(
	ctx context.Context,
	opts ExportBundleOptions,
) (*ExportBundleResult, error) {
	req := &platformv1.ExportBundleRequest{
		Id: opts.ID,
	}

	stream, err := a.client.ExportBundle(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "ExportBundle", Err: err}
	}

	var buf bytes.Buffer
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrGRPCStream{Operation: "ExportBundle.Recv", Err: err}
		}
		buf.Write(resp.GetData())
	}

	data := buf.Bytes()
	checksum := sha256.Sum256(data)

	result := &ExportBundleResult{
		Size:     int64(len(data)),
		Checksum: hex.EncodeToString(checksum[:]),
	}

	// Write to the specified output path or a temp file so that
	// the ArchivePath is always populated for downstream import tests.
	archivePath := opts.OutputPath
	if archivePath == "" {
		tmpFile, tmpErr := os.CreateTemp("", "vtpm-export-*.tar.gz")
		if tmpErr != nil {
			return nil, ErrGRPCStream{Operation: "ExportBundle.CreateTemp", Err: tmpErr}
		}
		archivePath = tmpFile.Name()
		tmpFile.Close()
	}
	if err := os.WriteFile(archivePath, data, 0600); err != nil {
		return nil, ErrGRPCStream{Operation: "ExportBundle.WriteFile", Err: err}
	}
	result.ArchivePath = archivePath

	return result, nil
}

// ImportBundle imports a bundle from a tar.gz archive via gRPC streaming.
func (a *GRPCAdapter) ImportBundle(
	ctx context.Context,
	opts ImportBundleOptions,
) (*ImportBundleResult, error) {
	var data []byte

	if opts.ArchivePath != "" {
		var err error
		data, err = os.ReadFile(opts.ArchivePath)
		if err != nil {
			return nil, ErrGRPCStream{Operation: "ImportBundle.ReadFile", Err: err}
		}
	} else if len(opts.ArchiveData) > 0 {
		data = opts.ArchiveData
	} else {
		return nil, ErrGRPCCall{Method: "ImportBundle", Err: ErrGRPCValidationFailed{Errors: []string{"archive path or data required"}}}
	}

	stream, err := a.client.ImportBundle(ctx)
	if err != nil {
		return nil, ErrGRPCCall{Method: "ImportBundle", Err: err}
	}

	const chunkSize = 32 * 1024 // 32KB chunks
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}

		if err := stream.Send(&platformv1.ImportBundleRequest{
			Data: data[i:end],
		}); err != nil {
			return nil, ErrGRPCStream{Operation: "ImportBundle.Send", Err: err}
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return nil, ErrGRPCStream{Operation: "ImportBundle.CloseAndRecv", Err: err}
	}

	return &ImportBundleResult{
		Bundle: protoToBundle(resp.GetBundle()),
	}, nil
}

// ============================================================================
// Validation Operations
// ============================================================================

// ValidateBundle validates bundle integrity via gRPC.
func (a *GRPCAdapter) ValidateBundle(
	ctx context.Context,
	opts ValidateBundleOptions,
) (*ValidateBundleResult, error) {
	req := &platformv1.ValidateBundleRequest{
		Id: opts.ID,
	}

	resp, err := a.client.ValidateBundle(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "ValidateBundle", Err: err}
	}

	// The gRPC server returns a successful response with Valid=false
	// when validation fails (including nonexistent bundles). Translate
	// this into an error so callers can distinguish success from failure.
	if !resp.GetValid() {
		return nil, ErrGRPCValidationFailed{Errors: resp.GetErrors()}
	}

	return &ValidateBundleResult{
		Valid:            resp.GetValid(),
		Errors:           resp.GetErrors(),
		ChecksumVerified: resp.GetValid(),
	}, nil
}

// ============================================================================
// Path Helper Operations
// ============================================================================

// GetBundlePath returns the filesystem path to a bundle via gRPC.
func (a *GRPCAdapter) GetBundlePath(
	ctx context.Context,
	opts GetBundlePathOptions,
) (*GetBundlePathResult, error) {
	req := &platformv1.GetBundlePathRequest{
		Id: opts.ID,
	}

	resp, err := a.client.GetBundlePath(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "GetBundlePath", Err: err}
	}

	return &GetBundlePathResult{
		Path: resp.GetPath(),
	}, nil
}

// GetTPMSocketPath returns the TPM socket path for a bundle via gRPC.
func (a *GRPCAdapter) GetTPMSocketPath(
	ctx context.Context,
	opts GetTPMSocketPathOptions,
) (*GetTPMSocketPathResult, error) {
	req := &platformv1.GetTPMSocketPathRequest{
		Id: opts.ID,
	}

	resp, err := a.client.GetTPMSocketPath(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "GetTPMSocketPath", Err: err}
	}

	return &GetTPMSocketPathResult{
		Path: resp.GetPath(),
	}, nil
}

// GetNVRAMPath returns the OVMF NVRAM path for a bundle via gRPC.
func (a *GRPCAdapter) GetNVRAMPath(
	ctx context.Context,
	opts GetNVRAMPathOptions,
) (*GetNVRAMPathResult, error) {
	req := &platformv1.GetNVRAMPathRequest{
		Id: opts.ID,
	}

	resp, err := a.client.GetNVRAMPath(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "GetNVRAMPath", Err: err}
	}

	return &GetNVRAMPathResult{
		Path: resp.GetPath(),
	}, nil
}

// ============================================================================
// Runtime TPM Operations
// ============================================================================

// Start starts the swtpm daemon for a bundle via gRPC.
func (a *GRPCAdapter) Start(ctx context.Context, opts StartOptions) (*StartResult, error) {
	req := &platformv1.StartVTPMRequest{
		BundleId: opts.BundleID,
	}

	resp, err := a.client.StartVTPM(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "StartVTPM", Err: err}
	}

	return &StartResult{
		BundleID:   resp.GetBundleId(),
		Running:    resp.GetRunning(),
		SocketPath: resp.GetSocketPath(),
	}, nil
}

// Stop stops the swtpm daemon for a bundle via gRPC.
func (a *GRPCAdapter) Stop(ctx context.Context, opts StopOptions) (*StopResult, error) {
	req := &platformv1.StopVTPMRequest{
		BundleId: opts.BundleID,
	}

	resp, err := a.client.StopVTPM(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "StopVTPM", Err: err}
	}

	return &StopResult{
		BundleID: resp.GetBundleId(),
		Stopped:  resp.GetStopped(),
	}, nil
}

// IsRunning checks if the vTPM for a bundle is running via gRPC.
func (a *GRPCAdapter) IsRunning(ctx context.Context, opts IsRunningOptions) (*IsRunningResult, error) {
	req := &platformv1.IsVTPMRunningRequest{
		BundleId: opts.BundleID,
	}

	resp, err := a.client.IsVTPMRunning(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "IsVTPMRunning", Err: err}
	}

	return &IsRunningResult{
		BundleID: resp.GetBundleId(),
		Running:  resp.GetRunning(),
	}, nil
}

// Quote generates a TPM quote over specified PCRs via gRPC.
func (a *GRPCAdapter) Quote(ctx context.Context, opts QuoteOptions) (*QuoteResult, error) {
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

	resp, err := a.client.QuoteVTPM(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "QuoteVTPM", Err: err}
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

// Seal encrypts data to the TPM, optionally binding to PCR values via gRPC.
func (a *GRPCAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
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

	resp, err := a.client.SealVTPM(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "SealVTPM", Err: err}
	}

	return &SealResult{
		BundleID:   resp.GetBundleId(),
		SealedData: resp.GetSealedData(),
	}, nil
}

// Unseal decrypts data that was previously sealed to the TPM via gRPC.
func (a *GRPCAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	req := &platformv1.UnsealVTPMRequest{
		BundleId:   opts.BundleID,
		SealedData: opts.SealedData,
		AuthValue:  opts.AuthValue,
	}

	resp, err := a.client.UnsealVTPM(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "UnsealVTPM", Err: err}
	}

	return &UnsealResult{
		BundleID: resp.GetBundleId(),
		Data:     resp.GetData(),
	}, nil
}

// ExtendPCR extends a PCR with the provided data via gRPC.
func (a *GRPCAdapter) ExtendPCR(ctx context.Context, opts ExtendPCROptions) (*ExtendPCRResult, error) {
	req := &platformv1.ExtendVTPMPCRRequest{
		BundleId: opts.BundleID,
		PcrIndex: int32(opts.PCRIndex),
		Data:     opts.Data,
	}

	resp, err := a.client.ExtendVTPMPCR(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "ExtendVTPMPCR", Err: err}
	}

	return &ExtendPCRResult{
		BundleID: resp.GetBundleId(),
		PCRIndex: int(resp.GetPcrIndex()),
		Extended: resp.GetExtended(),
	}, nil
}

// ReadPCR reads the current value of a PCR via gRPC.
func (a *GRPCAdapter) ReadPCR(ctx context.Context, opts ReadPCROptions) (*ReadPCRResult, error) {
	req := &platformv1.ReadVTPMPCRRequest{
		BundleId: opts.BundleID,
		PcrIndex: int32(opts.PCRIndex),
	}

	resp, err := a.client.ReadVTPMPCR(ctx, req)
	if err != nil {
		return nil, ErrGRPCCall{Method: "ReadVTPMPCR", Err: err}
	}

	return &ReadPCRResult{
		BundleID: resp.GetBundleId(),
		PCRIndex: int(resp.GetPcrIndex()),
		Value:    resp.GetValue(),
	}, nil
}

// ============================================================================
// Proto Conversion Helpers: Domain to Proto
// ============================================================================

// bundleModeToProto converts vtpm.BundleMode to proto BundleMode.
func bundleModeToProto(mode vtpm.BundleMode) platformv1.BundleMode {
	switch mode {
	case vtpm.BundleModeTemplate:
		return platformv1.BundleMode_BUNDLE_MODE_TEMPLATE
	case vtpm.BundleModePreAssigned:
		return platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED
	default:
		return platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED
	}
}

// ekAlgorithmToProto converts vtpm.EKAlgorithm to proto EKAlgorithm.
func ekAlgorithmToProto(alg vtpm.EKAlgorithm) platformv1.EKAlgorithm {
	switch alg {
	case vtpm.EKAlgorithmRSA:
		return platformv1.EKAlgorithm_EK_ALGORITHM_RSA
	case vtpm.EKAlgorithmECC:
		return platformv1.EKAlgorithm_EK_ALGORITHM_ECC
	default:
		return platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED
	}
}

// ============================================================================
// Proto Conversion Helpers: Proto to Domain
// ============================================================================

// protoToBundle converts proto Bundle to vtpm.Bundle.
func protoToBundle(pb *platformv1.Bundle) *vtpm.Bundle {
	if pb == nil {
		return nil
	}

	bundle := &vtpm.Bundle{
		ID:         pb.GetId(),
		Mode:       protoToBundleMode(pb.GetMode()),
		Manifest:   protoToManifest(pb.GetManifest()),
		TPMState:   protoToTPMState(pb.GetTpmState()),
		OVMFState:  protoToOVMFState(pb.GetOvmfState()),
		ClonedFrom: pb.GetClonedFrom(),
	}

	if pb.GetCreatedAt() != nil {
		bundle.CreatedAt = pb.GetCreatedAt().AsTime()
	}

	if pb.GetSecureBootKeys() != nil {
		bundle.SecureBootKeys = protoToSecureBootKeyPaths(pb.GetSecureBootKeys())
	}

	return bundle
}

// protoToTemplate converts proto Template to vtpm.Template.
func protoToTemplate(pt *platformv1.Template) *vtpm.Template {
	if pt == nil {
		return nil
	}

	template := &vtpm.Template{
		ID:                pt.GetId(),
		Description:       pt.GetDescription(),
		TPMStateDir:       pt.GetTpmStateDir(),
		NVRAMPath:         pt.GetNvramPath(),
		SecureBootKeysDir: pt.GetSecureBootKeysDir(),
		EKAlgorithm:       protoToEKAlgorithm(pt.GetEkAlgorithm()),
		SecureBootEnabled: pt.GetSecureBootEnabled(),
	}

	if pt.GetCreatedAt() != nil {
		template.CreatedAt = pt.GetCreatedAt().AsTime()
	}

	return template
}

// protoToBundleMode converts proto BundleMode to vtpm.BundleMode.
func protoToBundleMode(mode platformv1.BundleMode) vtpm.BundleMode {
	switch mode {
	case platformv1.BundleMode_BUNDLE_MODE_TEMPLATE:
		return vtpm.BundleModeTemplate
	case platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED:
		return vtpm.BundleModePreAssigned
	default:
		return ""
	}
}

// protoToEKAlgorithm converts proto EKAlgorithm to vtpm.EKAlgorithm.
func protoToEKAlgorithm(alg platformv1.EKAlgorithm) vtpm.EKAlgorithm {
	switch alg {
	case platformv1.EKAlgorithm_EK_ALGORITHM_RSA:
		return vtpm.EKAlgorithmRSA
	case platformv1.EKAlgorithm_EK_ALGORITHM_ECC:
		return vtpm.EKAlgorithmECC
	default:
		return vtpm.EKAlgorithmRSA
	}
}

// protoToManifest converts proto Manifest to vtpm.Manifest.
func protoToManifest(pm *platformv1.Manifest) *vtpm.Manifest {
	if pm == nil {
		return nil
	}

	manifest := &vtpm.Manifest{
		Version:           pm.GetVersion(),
		ID:                pm.GetId(),
		Mode:              protoToBundleMode(pm.GetMode()),
		Hostname:          pm.GetHostname(),
		EKAlgorithm:       protoToEKAlgorithm(pm.GetEkAlgorithm()),
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
		manifest.EKCertificate = protoToEKCertInfo(pm.GetEkCertificate())
	}

	if pm.GetSecureBootKeys() != nil {
		manifest.SecureBootKeys = protoToSecureBootKeyInfo(pm.GetSecureBootKeys())
	}

	return manifest
}

// protoToEKCertInfo converts proto EKCertInfo to vtpm.EKCertInfo.
func protoToEKCertInfo(pc *platformv1.EKCertInfo) *vtpm.EKCertInfo {
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

// protoToSecureBootKeyInfo converts proto SecureBootKeyInfo to vtpm.SecureBootKeyInfo.
func protoToSecureBootKeyInfo(ps *platformv1.SecureBootKeyInfo) *vtpm.SecureBootKeyInfo {
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

// protoToSecureBootKeyPaths converts proto SecureBootKeyPaths to vtpm.SecureBootKeyPaths.
func protoToSecureBootKeyPaths(ps *platformv1.SecureBootKeyPaths) *vtpm.SecureBootKeyPaths {
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

// protoToTPMState converts proto TPMState to vtpm.TPMState.
func protoToTPMState(pt *platformv1.TPMState) *vtpm.TPMState {
	if pt == nil {
		return nil
	}

	return &vtpm.TPMState{
		StateDir:     pt.GetStateDir(),
		PermallFile:  pt.GetPermallFile(),
		VolatileFile: pt.GetVolatileFile(),
	}
}

// protoToOVMFState converts proto OVMFState to vtpm.OVMFState.
func protoToOVMFState(po *platformv1.OVMFState) *vtpm.OVMFState {
	if po == nil {
		return nil
	}

	return &vtpm.OVMFState{
		NVRAMFile: po.GetNvramFile(),
	}
}

// ============================================================================
// Interface Verification
// ============================================================================

// Verify GRPCAdapter implements VTPMCommands interface.
var _ VTPMCommands = (*GRPCAdapter)(nil)
