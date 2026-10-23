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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	// exportChunkSize is the size of chunks for streaming export data.
	exportChunkSize = 32 * 1024 // 32KB chunks
)

// VTPMServiceServer implements the gRPC VTPMService interface.
// It wraps the vtpm.VTPMService interface to provide gRPC access to vTPM operations.
type VTPMServiceServer struct {
	platformv1.UnimplementedVTPMServiceServer
	service vtpm.VTPMService
	logger  *slog.Logger
}

// NewVTPMServiceServer creates a new VTPMServiceServer.
func NewVTPMServiceServer(service vtpm.VTPMService, logger *slog.Logger) *VTPMServiceServer {
	return &VTPMServiceServer{
		service: service,
		logger:  logger,
	}
}

// CreateBundle creates a new vTPM bundle.
func (s *VTPMServiceServer) CreateBundle(
	ctx context.Context,
	req *platformv1.CreateBundleRequest,
) (*platformv1.CreateBundleResponse, error) {

	if req.GetOptions() == nil {
		return nil, status.Error(codes.InvalidArgument, "options are required")
	}

	opts := s.protoToCreateBundleOptions(req.GetOptions())

	bundle, err := s.service.CreateBundle(ctx, opts)
	if err != nil {
		s.logger.Error("CreateBundle failed", "error", err)
		return nil, s.mapError(err)
	}

	return &platformv1.CreateBundleResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "bundle created successfully",
		},
		Bundle: s.bundleToProto(bundle),
	}, nil
}

// GetBundle retrieves a bundle by ID.
func (s *VTPMServiceServer) GetBundle(
	ctx context.Context,
	req *platformv1.GetBundleRequest,
) (*platformv1.GetBundleResponse, error) {

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle id is required")
	}

	bundle, err := s.service.GetBundle(ctx, req.GetId())
	if err != nil {
		s.logger.Error("GetBundle failed", "error", err, "id", req.GetId())
		return nil, s.mapError(err)
	}

	return &platformv1.GetBundleResponse{
		Bundle: s.bundleToProto(bundle),
	}, nil
}

// DeleteBundle deletes a bundle.
func (s *VTPMServiceServer) DeleteBundle(
	ctx context.Context,
	req *platformv1.DeleteBundleRequest,
) (*platformv1.DeleteBundleResponse, error) {

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle id is required")
	}

	err := s.service.DeleteBundle(ctx, req.GetId())
	if err != nil {
		s.logger.Error("DeleteBundle failed", "error", err, "id", req.GetId())
		return nil, s.mapError(err)
	}

	return &platformv1.DeleteBundleResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "bundle deleted successfully",
		},
	}, nil
}

// ListBundles lists bundles matching the filter options.
func (s *VTPMServiceServer) ListBundles(
	ctx context.Context,
	req *platformv1.ListBundlesRequest,
) (*platformv1.ListBundlesResponse, error) {

	opts := s.protoToListOptions(req.GetOptions())

	bundles, err := s.service.ListBundles(ctx, opts)
	if err != nil {
		s.logger.Error("ListBundles failed", "error", err)
		return nil, s.mapError(err)
	}

	protoBundles := make([]*platformv1.Bundle, 0, len(bundles))
	for _, bundle := range bundles {
		protoBundles = append(protoBundles, s.bundleToProto(bundle))
	}

	return &platformv1.ListBundlesResponse{
		Bundles: protoBundles,
		Total:   int32(len(bundles)),
	}, nil
}

// CreateTemplate creates a new vTPM template.
func (s *VTPMServiceServer) CreateTemplate(
	ctx context.Context,
	req *platformv1.CreateTemplateRequest,
) (*platformv1.CreateTemplateResponse, error) {

	if req.GetOptions() == nil {
		return nil, status.Error(codes.InvalidArgument, "options are required")
	}

	opts := s.protoToCreateTemplateOptions(req.GetOptions())

	template, err := s.service.CreateTemplate(ctx, opts)
	if err != nil {
		s.logger.Error("CreateTemplate failed", "error", err)
		return nil, s.mapError(err)
	}

	return &platformv1.CreateTemplateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "template created successfully",
		},
		Template: s.templateToProto(template),
	}, nil
}

// GetTemplate retrieves a template by ID.
func (s *VTPMServiceServer) GetTemplate(
	ctx context.Context,
	req *platformv1.GetTemplateRequest,
) (*platformv1.GetTemplateResponse, error) {

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "template id is required")
	}

	template, err := s.service.GetTemplate(ctx, req.GetId())
	if err != nil {
		s.logger.Error("GetTemplate failed", "error", err, "id", req.GetId())
		return nil, s.mapError(err)
	}

	return &platformv1.GetTemplateResponse{
		Template: s.templateToProto(template),
	}, nil
}

// DeleteTemplate deletes a template.
func (s *VTPMServiceServer) DeleteTemplate(
	ctx context.Context,
	req *platformv1.DeleteTemplateRequest,
) (*platformv1.DeleteTemplateResponse, error) {

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "template id is required")
	}

	err := s.service.DeleteTemplate(ctx, req.GetId())
	if err != nil {
		s.logger.Error("DeleteTemplate failed", "error", err, "id", req.GetId())
		return nil, s.mapError(err)
	}

	return &platformv1.DeleteTemplateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "template deleted successfully",
		},
	}, nil
}

// ListTemplates lists all templates.
func (s *VTPMServiceServer) ListTemplates(
	ctx context.Context,
	req *platformv1.ListTemplatesRequest,
) (*platformv1.ListTemplatesResponse, error) {

	templates, err := s.service.ListTemplates(ctx)
	if err != nil {
		s.logger.Error("ListTemplates failed", "error", err)
		return nil, s.mapError(err)
	}

	protoTemplates := make([]*platformv1.Template, 0, len(templates))
	for _, template := range templates {
		protoTemplates = append(protoTemplates, s.templateToProto(template))
	}

	return &platformv1.ListTemplatesResponse{
		Templates: protoTemplates,
	}, nil
}

// CloneTemplate clones a template to create a new bundle with identity.
func (s *VTPMServiceServer) CloneTemplate(
	ctx context.Context,
	req *platformv1.CloneTemplateRequest,
) (*platformv1.CloneTemplateResponse, error) {

	if req.GetOptions() == nil {
		return nil, status.Error(codes.InvalidArgument, "options are required")
	}

	opts := s.protoToCloneOptions(req.GetOptions())

	bundle, err := s.service.CloneTemplate(ctx, opts)
	if err != nil {
		s.logger.Error("CloneTemplate failed", "error", err)
		return nil, s.mapError(err)
	}

	return &platformv1.CloneTemplateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "template cloned successfully",
		},
		Bundle: s.bundleToProto(bundle),
	}, nil
}

// ExportBundle exports a bundle to a tar.gz archive.
func (s *VTPMServiceServer) ExportBundle(
	req *platformv1.ExportBundleRequest,
	stream platformv1.VTPMService_ExportBundleServer,
) error {

	if req.GetId() == "" {
		return status.Error(codes.InvalidArgument, "bundle id is required")
	}

	// Create a buffer to hold the exported data
	var buf bytes.Buffer

	err := s.service.ExportBundle(stream.Context(), req.GetId(), &buf)
	if err != nil {
		s.logger.Error("ExportBundle failed", "error", err, "id", req.GetId())
		return s.mapError(err)
	}

	// Stream the data in chunks
	data := buf.Bytes()
	for i := 0; i < len(data); i += exportChunkSize {
		end := i + exportChunkSize
		if end > len(data) {
			end = len(data)
		}

		err := stream.Send(&platformv1.ExportBundleResponse{
			Data: data[i:end],
		})
		if err != nil {
			s.logger.Error("ExportBundle stream send failed", "error", err)
			return status.Error(codes.Internal, "failed to stream export data")
		}
	}

	return nil
}

// ImportBundle imports a bundle from a tar.gz archive.
func (s *VTPMServiceServer) ImportBundle(
	stream platformv1.VTPMService_ImportBundleServer,
) error {

	// Collect all chunks
	var buf bytes.Buffer

	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.logger.Error("ImportBundle stream recv failed", "error", err)
			return status.Error(codes.Internal, "failed to receive import data")
		}

		_, err = buf.Write(chunk.GetData())
		if err != nil {
			s.logger.Error("ImportBundle buffer write failed", "error", err)
			return status.Error(codes.Internal, "failed to buffer import data")
		}
	}

	bundle, err := s.service.ImportBundle(stream.Context(), &buf)
	if err != nil {
		s.logger.Error("ImportBundle failed", "error", err)
		return s.mapError(err)
	}

	return stream.SendAndClose(&platformv1.ImportBundleResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "bundle imported successfully",
		},
		Bundle: s.bundleToProto(bundle),
	})
}

// ValidateBundle validates bundle integrity.
func (s *VTPMServiceServer) ValidateBundle(
	ctx context.Context,
	req *platformv1.ValidateBundleRequest,
) (*platformv1.ValidateBundleResponse, error) {

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle id is required")
	}

	err := s.service.ValidateBundle(ctx, req.GetId())
	if err != nil {
		s.logger.Debug("ValidateBundle found issues", "error", err, "id", req.GetId())
		return &platformv1.ValidateBundleResponse{
			Status: &platformv1.Status{
				Success: false,
				Message: "bundle validation failed",
			},
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	return &platformv1.ValidateBundleResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "bundle is valid",
		},
		Valid:  true,
		Errors: nil,
	}, nil
}

// GetBundlePath returns the filesystem path to a bundle.
func (s *VTPMServiceServer) GetBundlePath(
	ctx context.Context,
	req *platformv1.GetBundlePathRequest,
) (*platformv1.GetBundlePathResponse, error) {

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle id is required")
	}

	path := s.service.GetBundlePath(req.GetId())

	return &platformv1.GetBundlePathResponse{
		Path: path,
	}, nil
}

// GetTPMSocketPath returns the TPM socket path for a bundle.
func (s *VTPMServiceServer) GetTPMSocketPath(
	ctx context.Context,
	req *platformv1.GetTPMSocketPathRequest,
) (*platformv1.GetTPMSocketPathResponse, error) {

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle id is required")
	}

	path := s.service.GetTPMSocketPath(req.GetId())

	return &platformv1.GetTPMSocketPathResponse{
		Path: path,
	}, nil
}

// GetNVRAMPath returns the OVMF NVRAM path for a bundle.
func (s *VTPMServiceServer) GetNVRAMPath(
	ctx context.Context,
	req *platformv1.GetNVRAMPathRequest,
) (*platformv1.GetNVRAMPathResponse, error) {

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle id is required")
	}

	path := s.service.GetNVRAMPath(req.GetId())

	return &platformv1.GetNVRAMPathResponse{
		Path: path,
	}, nil
}

// =============================================================================
// Runtime TPM operations
//
// These delegate to the same vtpm.VTPMService the REST / QUIC / MCP handlers
// use, closing the gRPC/Unix runtime-op gap: before this the pb server fell
// through to UnimplementedVTPMServiceServer and returned codes.Unimplemented
// for Start/Stop/IsRunning/Quote/Seal/Unseal/ExtendPCR/ReadPCR.
// =============================================================================

// StartVTPM starts the swtpm daemon for the specified bundle.
func (s *VTPMServiceServer) StartVTPM(
	ctx context.Context,
	req *platformv1.StartVTPMRequest,
) (*platformv1.StartVTPMResponse, error) {

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle_id is required")
	}

	if err := s.service.Start(ctx, req.GetBundleId()); err != nil {
		s.logger.Error("StartVTPM failed", "error", err, "bundle_id", req.GetBundleId())
		return nil, s.mapError(err)
	}

	return &platformv1.StartVTPMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "vTPM started successfully",
		},
		BundleId:   req.GetBundleId(),
		Running:    s.service.IsRunning(req.GetBundleId()),
		SocketPath: s.service.GetTPMSocketPath(req.GetBundleId()),
	}, nil
}

// StopVTPM stops the swtpm daemon for the specified bundle.
func (s *VTPMServiceServer) StopVTPM(
	ctx context.Context,
	req *platformv1.StopVTPMRequest,
) (*platformv1.StopVTPMResponse, error) {

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle_id is required")
	}

	if err := s.service.Stop(ctx, req.GetBundleId()); err != nil {
		s.logger.Error("StopVTPM failed", "error", err, "bundle_id", req.GetBundleId())
		return nil, s.mapError(err)
	}

	return &platformv1.StopVTPMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "vTPM stopped successfully",
		},
		BundleId: req.GetBundleId(),
		Stopped:  !s.service.IsRunning(req.GetBundleId()),
	}, nil
}

// IsVTPMRunning reports whether the swtpm daemon for a bundle is running.
func (s *VTPMServiceServer) IsVTPMRunning(
	ctx context.Context,
	req *platformv1.IsVTPMRunningRequest,
) (*platformv1.IsVTPMRunningResponse, error) {

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle_id is required")
	}

	return &platformv1.IsVTPMRunningResponse{
		BundleId: req.GetBundleId(),
		Running:  s.service.IsRunning(req.GetBundleId()),
	}, nil
}

// QuoteVTPM generates a TPM quote over the requested PCRs.
func (s *VTPMServiceServer) QuoteVTPM(
	ctx context.Context,
	req *platformv1.QuoteVTPMRequest,
) (*platformv1.QuoteVTPMResponse, error) {

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle_id is required")
	}

	result, err := s.service.Quote(ctx, req.GetBundleId(), req.GetNonce(), int32SliceToInt(req.GetPcrs()))
	if err != nil {
		s.logger.Error("QuoteVTPM failed", "error", err, "bundle_id", req.GetBundleId())
		return nil, s.mapError(err)
	}

	pcrValues := make(map[int32][]byte, len(result.PCRValues))
	for idx, val := range result.PCRValues {
		pcrValues[int32(idx)] = val
	}

	return &platformv1.QuoteVTPMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "quote generated successfully",
		},
		BundleId:      req.GetBundleId(),
		Quote:         result.Quote,
		Signature:     result.Signature,
		PcrValues:     pcrValues,
		HashAlgorithm: result.HashAlgorithm,
	}, nil
}

// SealVTPM seals data to the TPM, optionally binding it to PCR values.
func (s *VTPMServiceServer) SealVTPM(
	ctx context.Context,
	req *platformv1.SealVTPMRequest,
) (*platformv1.SealVTPMResponse, error) {

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle_id is required")
	}

	opts := &vtpm.SealOptions{
		PCRs:      int32SliceToInt(req.GetPcrs()),
		AuthValue: req.GetAuthValue(),
	}

	sealed, err := s.service.Seal(ctx, req.GetBundleId(), req.GetData(), opts)
	if err != nil {
		s.logger.Error("SealVTPM failed", "error", err, "bundle_id", req.GetBundleId())
		return nil, s.mapError(err)
	}

	return &platformv1.SealVTPMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "data sealed successfully",
		},
		BundleId:   req.GetBundleId(),
		SealedData: sealed,
	}, nil
}

// UnsealVTPM unseals data previously sealed to the TPM.
func (s *VTPMServiceServer) UnsealVTPM(
	ctx context.Context,
	req *platformv1.UnsealVTPMRequest,
) (*platformv1.UnsealVTPMResponse, error) {

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle_id is required")
	}

	data, err := s.service.Unseal(ctx, req.GetBundleId(), req.GetSealedData(), req.GetAuthValue())
	if err != nil {
		s.logger.Error("UnsealVTPM failed", "error", err, "bundle_id", req.GetBundleId())
		return nil, s.mapError(err)
	}

	return &platformv1.UnsealVTPMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "data unsealed successfully",
		},
		BundleId: req.GetBundleId(),
		Data:     data,
	}, nil
}

// ExtendVTPMPCR extends a PCR with the provided data.
func (s *VTPMServiceServer) ExtendVTPMPCR(
	ctx context.Context,
	req *platformv1.ExtendVTPMPCRRequest,
) (*platformv1.ExtendVTPMPCRResponse, error) {

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle_id is required")
	}

	if err := s.service.ExtendPCR(ctx, req.GetBundleId(), int(req.GetPcrIndex()), req.GetData()); err != nil {
		s.logger.Error("ExtendVTPMPCR failed", "error", err, "bundle_id", req.GetBundleId())
		return nil, s.mapError(err)
	}

	return &platformv1.ExtendVTPMPCRResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "PCR extended successfully",
		},
		BundleId: req.GetBundleId(),
		PcrIndex: req.GetPcrIndex(),
		Extended: true,
	}, nil
}

// ReadVTPMPCR reads the current value of a PCR.
func (s *VTPMServiceServer) ReadVTPMPCR(
	ctx context.Context,
	req *platformv1.ReadVTPMPCRRequest,
) (*platformv1.ReadVTPMPCRResponse, error) {

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle_id is required")
	}

	value, err := s.service.ReadPCR(ctx, req.GetBundleId(), int(req.GetPcrIndex()))
	if err != nil {
		s.logger.Error("ReadVTPMPCR failed", "error", err, "bundle_id", req.GetBundleId())
		return nil, s.mapError(err)
	}

	return &platformv1.ReadVTPMPCRResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "PCR read successfully",
		},
		BundleId: req.GetBundleId(),
		PcrIndex: req.GetPcrIndex(),
		Value:    value,
	}, nil
}

// int32SliceToInt converts a proto []int32 PCR list to the []int the service
// layer expects.
func int32SliceToInt(in []int32) []int {
	if len(in) == 0 {
		return nil
	}
	out := make([]int, len(in))
	for i, v := range in {
		out[i] = int(v)
	}
	return out
}

// Conversion helpers: proto to service types

func (s *VTPMServiceServer) protoToCreateBundleOptions(opts *platformv1.CreateBundleOptions) *vtpm.CreateBundleOptions {
	return &vtpm.CreateBundleOptions{
		Mode:              s.protoToBundleMode(opts.GetMode()),
		Hostname:          opts.GetHostname(),
		EKAlgorithm:       s.protoToEKAlgorithm(opts.GetEkAlgorithm()),
		SecureBootEnabled: opts.GetSecureBootEnabled(),
		Labels:            opts.GetLabels(),
		TemplateID:        opts.GetTemplateId(),
		DeviceProfileID:   opts.GetDeviceProfileId(),
	}
}

func (s *VTPMServiceServer) protoToCreateTemplateOptions(opts *platformv1.CreateTemplateOptions) *vtpm.CreateTemplateOptions {
	return &vtpm.CreateTemplateOptions{
		ID:                opts.GetId(),
		Description:       opts.GetDescription(),
		EKAlgorithm:       s.protoToEKAlgorithm(opts.GetEkAlgorithm()),
		SecureBootEnabled: opts.GetSecureBootEnabled(),
	}
}

func (s *VTPMServiceServer) protoToCloneOptions(opts *platformv1.CloneOptions) *vtpm.CloneOptions {
	return &vtpm.CloneOptions{
		TemplateID: opts.GetTemplateId(),
		Hostname:   opts.GetHostname(),
		Labels:     opts.GetLabels(),
	}
}

func (s *VTPMServiceServer) protoToListOptions(opts *platformv1.ListBundleOptions) *vtpm.ListOptions {
	if opts == nil {
		return nil
	}
	return &vtpm.ListOptions{
		Mode:            s.protoToBundleMode(opts.GetMode()),
		Labels:          opts.GetLabels(),
		Limit:           int(opts.GetLimit()),
		Offset:          int(opts.GetOffset()),
		DeviceProfileID: opts.GetDeviceProfileId(),
	}
}

func (s *VTPMServiceServer) protoToBundleMode(mode platformv1.BundleMode) vtpm.BundleMode {
	switch mode {
	case platformv1.BundleMode_BUNDLE_MODE_TEMPLATE:
		return vtpm.BundleModeTemplate
	case platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED:
		return vtpm.BundleModePreAssigned
	default:
		return ""
	}
}

// protoToEKAlgorithm maps the wire enum to the service algorithm.
// UNSPECIFIED is the empty algorithm, which the service replaces with its
// configured default. An enum value this server does not know is passed
// through by name so the service rejects it with ErrInvalidEKAlgorithm
// instead of silently creating an RSA EK.
func (s *VTPMServiceServer) protoToEKAlgorithm(alg platformv1.EKAlgorithm) vtpm.EKAlgorithm {
	switch alg {
	case platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED:
		return ""
	case platformv1.EKAlgorithm_EK_ALGORITHM_RSA:
		return vtpm.EKAlgorithmRSA
	case platformv1.EKAlgorithm_EK_ALGORITHM_ECC:
		return vtpm.EKAlgorithmECC
	default:
		return vtpm.EKAlgorithm(alg.String())
	}
}

// Conversion helpers: service types to proto

func (s *VTPMServiceServer) bundleToProto(bundle *vtpm.Bundle) *platformv1.Bundle {
	if bundle == nil {
		return nil
	}

	pb := &platformv1.Bundle{
		Id:         bundle.ID,
		Mode:       s.bundleModeToProto(bundle.Mode),
		Manifest:   s.manifestToProto(bundle.Manifest),
		TpmState:   s.tpmStateToProto(bundle.TPMState),
		OvmfState:  s.ovmfStateToProto(bundle.OVMFState),
		CreatedAt:  timestamppb.New(bundle.CreatedAt),
		ClonedFrom: bundle.ClonedFrom,
	}

	if bundle.SecureBootKeys != nil {
		pb.SecureBootKeys = s.secureBootKeyPathsToProto(bundle.SecureBootKeys)
	}

	return pb
}

func (s *VTPMServiceServer) templateToProto(template *vtpm.Template) *platformv1.Template {
	if template == nil {
		return nil
	}

	return &platformv1.Template{
		Id:                template.ID,
		Description:       template.Description,
		TpmStateDir:       template.TPMStateDir,
		NvramPath:         template.NVRAMPath,
		SecureBootKeysDir: template.SecureBootKeysDir,
		EkAlgorithm:       s.ekAlgorithmToProto(template.EKAlgorithm),
		SecureBootEnabled: template.SecureBootEnabled,
		CreatedAt:         timestamppb.New(template.CreatedAt),
	}
}

func (s *VTPMServiceServer) manifestToProto(manifest *vtpm.Manifest) *platformv1.Manifest {
	if manifest == nil {
		return nil
	}

	pb := &platformv1.Manifest{
		Version:           manifest.Version,
		Id:                manifest.ID,
		Mode:              s.bundleModeToProto(manifest.Mode),
		Hostname:          manifest.Hostname,
		CreatedAt:         timestamppb.New(manifest.CreatedAt),
		EkAlgorithm:       s.ekAlgorithmToProto(manifest.EKAlgorithm),
		EkHandle:          manifest.EKHandle,
		SecureBootEnabled: manifest.SecureBootEnabled,
		Checksums:         manifest.Checksums,
		Labels:            manifest.Labels,
		ClonedFrom:        manifest.ClonedFrom,
		DeviceProfileId:   manifest.DeviceProfileID,
	}

	if manifest.EKCertificate != nil {
		pb.EkCertificate = s.ekCertInfoToProto(manifest.EKCertificate)
	}

	if manifest.SecureBootKeys != nil {
		pb.SecureBootKeys = s.secureBootKeyInfoToProto(manifest.SecureBootKeys)
	}

	return pb
}

func (s *VTPMServiceServer) ekCertInfoToProto(info *vtpm.EKCertInfo) *platformv1.EKCertInfo {
	if info == nil {
		return nil
	}

	return &platformv1.EKCertInfo{
		Subject:      info.Subject,
		Issuer:       info.Issuer,
		SerialNumber: info.SerialNumber,
		NotBefore:    timestamppb.New(info.NotBefore),
		NotAfter:     timestamppb.New(info.NotAfter),
		Fingerprint:  info.Fingerprint,
	}
}

func (s *VTPMServiceServer) secureBootKeyInfoToProto(info *vtpm.SecureBootKeyInfo) *platformv1.SecureBootKeyInfo {
	if info == nil {
		return nil
	}

	return &platformv1.SecureBootKeyInfo{
		PkFingerprint:  info.PKFingerprint,
		KekFingerprint: info.KEKFingerprint,
		DbFingerprint:  info.DBFingerprint,
		OwnerGuid:      info.OwnerGUID,
	}
}

func (s *VTPMServiceServer) secureBootKeyPathsToProto(paths *vtpm.SecureBootKeyPaths) *platformv1.SecureBootKeyPaths {
	if paths == nil {
		return nil
	}

	return &platformv1.SecureBootKeyPaths{
		Dir:    paths.Dir,
		PkKey:  paths.PKKey,
		PkCrt:  paths.PKCert,
		KekKey: paths.KEKKey,
		KekCrt: paths.KEKCert,
		DbKey:  paths.DBKey,
		DbCrt:  paths.DBCert,
	}
}

func (s *VTPMServiceServer) tpmStateToProto(state *vtpm.TPMState) *platformv1.TPMState {
	if state == nil {
		return nil
	}

	return &platformv1.TPMState{
		StateDir:     state.StateDir,
		PermallFile:  state.PermallFile,
		VolatileFile: state.VolatileFile,
	}
}

func (s *VTPMServiceServer) ovmfStateToProto(state *vtpm.OVMFState) *platformv1.OVMFState {
	if state == nil {
		return nil
	}

	return &platformv1.OVMFState{
		NvramFile: state.NVRAMFile,
	}
}

func (s *VTPMServiceServer) bundleModeToProto(mode vtpm.BundleMode) platformv1.BundleMode {
	switch mode {
	case vtpm.BundleModeTemplate:
		return platformv1.BundleMode_BUNDLE_MODE_TEMPLATE
	case vtpm.BundleModePreAssigned:
		return platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED
	default:
		return platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED
	}
}

func (s *VTPMServiceServer) ekAlgorithmToProto(alg vtpm.EKAlgorithm) platformv1.EKAlgorithm {
	switch alg {
	case vtpm.EKAlgorithmRSA:
		return platformv1.EKAlgorithm_EK_ALGORITHM_RSA
	case vtpm.EKAlgorithmECC:
		return platformv1.EKAlgorithm_EK_ALGORITHM_ECC
	default:
		return platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED
	}
}

// mapError converts service errors to gRPC status errors.
func (s *VTPMServiceServer) mapError(err error) error {
	return mapVTPMError(err)
}

// mapVTPMError classes a vTPM service error as a gRPC status. The gRPC
// VTPMService and the MCP vTPM tools share it so both transports answer the
// same input with the same error class.
func mapVTPMError(err error) error {
	if err == nil {
		return nil
	}

	// Check for known error types and map to appropriate gRPC codes
	errMsg := err.Error()

	var invalidEKAlgorithm vtpm.ErrInvalidEKAlgorithm
	if errors.As(err, &invalidEKAlgorithm) {
		return status.Error(codes.InvalidArgument, errMsg)
	}

	// A bundle that is not in the state the operation needs (REST 409).
	var notRunning vtpm.ErrVTPMNotRunning
	var alreadyRunning vtpm.ErrVTPMAlreadyRunning
	if errors.As(err, &notRunning) || errors.As(err, &alreadyRunning) {
		return status.Error(codes.FailedPrecondition, errMsg)
	}

	// Check for not found errors
	if containsAny(errMsg, "not found", "does not exist", "no such") {
		return status.Error(codes.NotFound, errMsg)
	}

	// Check for already exists errors
	if containsAny(errMsg, "already exists", "duplicate") {
		return status.Error(codes.AlreadyExists, errMsg)
	}

	// Check for invalid argument errors
	if containsAny(errMsg, "invalid", "required", "must be", "cannot be") {
		return status.Error(codes.InvalidArgument, errMsg)
	}

	// Check for permission errors
	if containsAny(errMsg, "permission", "denied", "unauthorized", "forbidden") {
		return status.Error(codes.PermissionDenied, errMsg)
	}

	// Default to internal error
	return status.Error(codes.Internal, errMsg)
}

// containsAny checks if the string contains any of the substrings.
func containsAny(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
