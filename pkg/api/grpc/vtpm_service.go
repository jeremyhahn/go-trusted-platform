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
	"io"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// vtpmExportChunkSize is the size of chunks for streaming export data.
	vtpmExportChunkSize = 32 * 1024 // 32KB chunks
)

// vTPM gRPC service error types.

// ErrNilVTPMService is returned when the vTPM service is nil.
type ErrNilVTPMService struct{}

func (e ErrNilVTPMService) Error() string {
	return "vtpm service is nil"
}

// ErrMissingBundleID is returned when a bundle ID is required but not provided.
type ErrMissingBundleID struct{}

func (e ErrMissingBundleID) Error() string {
	return "bundle id is required"
}

// ErrMissingTemplateID is returned when a template ID is required but not provided.
type ErrMissingTemplateID struct{}

func (e ErrMissingTemplateID) Error() string {
	return "template id is required"
}

// ErrMissingOptions is returned when options are required but not provided.
type ErrMissingOptions struct{}

func (e ErrMissingOptions) Error() string {
	return "options are required"
}

// ErrMissingCloneOptions is returned when clone options are required but not provided.
type ErrMissingCloneOptions struct{}

func (e ErrMissingCloneOptions) Error() string {
	return "clone options are required"
}

// ErrStreamSendFailed is returned when sending data on a stream fails.
type ErrStreamSendFailed struct {
	Operation string
	Cause     error
}

func (e ErrStreamSendFailed) Error() string {
	return "stream send failed during " + e.Operation + ": " + e.Cause.Error()
}

// ErrStreamRecvFailed is returned when receiving data from a stream fails.
type ErrStreamRecvFailed struct {
	Operation string
	Cause     error
}

func (e ErrStreamRecvFailed) Error() string {
	return "stream receive failed during " + e.Operation + ": " + e.Cause.Error()
}

// ErrMissingSealData is returned when seal data is required but not provided.
type ErrMissingSealData struct{}

func (e ErrMissingSealData) Error() string {
	return "data to seal is required"
}

// ErrMissingSealedData is returned when sealed data is required but not provided.
type ErrMissingSealedData struct{}

func (e ErrMissingSealedData) Error() string {
	return "sealed data is required"
}

// ErrMissingNonce is returned when a nonce is required but not provided.
type ErrMissingNonce struct{}

func (e ErrMissingNonce) Error() string {
	return "nonce is required"
}

// ErrMissingPCRs is returned when PCR indices are required but not provided.
type ErrMissingPCRs struct{}

func (e ErrMissingPCRs) Error() string {
	return "pcr indices are required"
}

// ErrMissingExtendData is returned when PCR extend data is required but not provided.
type ErrMissingExtendData struct{}

func (e ErrMissingExtendData) Error() string {
	return "data to extend into PCR is required"
}

// VTPMGRPCService implements the gRPC VTPMService server interface.
// It wraps the vtpm.VTPMService interface to provide gRPC access to vTPM operations.
type VTPMGRPCService struct {
	platformv1.UnimplementedVTPMServiceServer
	logger  *logging.Logger
	service vtpm.VTPMService
}

// NewVTPMGRPCService creates a new VTPMGRPCService instance.
func NewVTPMGRPCService(
	logger *logging.Logger,
	service vtpm.VTPMService,
) *VTPMGRPCService {
	return &VTPMGRPCService{
		logger:  logger,
		service: service,
	}
}

// CreateBundle creates a new vTPM bundle.
func (s *VTPMGRPCService) CreateBundle(
	ctx context.Context,
	req *platformv1.CreateBundleRequest,
) (*platformv1.CreateBundleResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetOptions() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingOptions{}.Error())
	}

	opts := s.protoToCreateBundleOptions(req.GetOptions())

	bundle, err := s.service.CreateBundle(ctx, opts)
	if err != nil {
		return nil, s.mapError("CreateBundle", err)
	}

	return &platformv1.CreateBundleResponse{
		Status: successStatusVTPM("bundle created successfully"),
		Bundle: s.bundleToProto(bundle),
	}, nil
}

// GetBundle retrieves a bundle by ID.
func (s *VTPMGRPCService) GetBundle(
	ctx context.Context,
	req *platformv1.GetBundleRequest,
) (*platformv1.GetBundleResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	bundle, err := s.service.GetBundle(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("GetBundle", err)
	}

	return &platformv1.GetBundleResponse{
		Bundle: s.bundleToProto(bundle),
	}, nil
}

// DeleteBundle deletes a bundle.
func (s *VTPMGRPCService) DeleteBundle(
	ctx context.Context,
	req *platformv1.DeleteBundleRequest,
) (*platformv1.DeleteBundleResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	err := s.service.DeleteBundle(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("DeleteBundle", err)
	}

	return &platformv1.DeleteBundleResponse{
		Status: successStatusVTPM("bundle deleted successfully"),
	}, nil
}

// ListBundles lists bundles matching the filter options.
func (s *VTPMGRPCService) ListBundles(
	ctx context.Context,
	req *platformv1.ListBundlesRequest,
) (*platformv1.ListBundlesResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	opts := s.protoToListOptions(req.GetOptions())

	bundles, err := s.service.ListBundles(ctx, opts)
	if err != nil {
		return nil, s.mapError("ListBundles", err)
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
func (s *VTPMGRPCService) CreateTemplate(
	ctx context.Context,
	req *platformv1.CreateTemplateRequest,
) (*platformv1.CreateTemplateResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetOptions() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingOptions{}.Error())
	}

	opts := s.protoToCreateTemplateOptions(req.GetOptions())

	template, err := s.service.CreateTemplate(ctx, opts)
	if err != nil {
		return nil, s.mapError("CreateTemplate", err)
	}

	return &platformv1.CreateTemplateResponse{
		Status:   successStatusVTPM("template created successfully"),
		Template: s.templateToProto(template),
	}, nil
}

// GetTemplate retrieves a template by ID.
func (s *VTPMGRPCService) GetTemplate(
	ctx context.Context,
	req *platformv1.GetTemplateRequest,
) (*platformv1.GetTemplateResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTemplateID{}.Error())
	}

	template, err := s.service.GetTemplate(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("GetTemplate", err)
	}

	return &platformv1.GetTemplateResponse{
		Template: s.templateToProto(template),
	}, nil
}

// DeleteTemplate deletes a template.
func (s *VTPMGRPCService) DeleteTemplate(
	ctx context.Context,
	req *platformv1.DeleteTemplateRequest,
) (*platformv1.DeleteTemplateResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingTemplateID{}.Error())
	}

	err := s.service.DeleteTemplate(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("DeleteTemplate", err)
	}

	return &platformv1.DeleteTemplateResponse{
		Status: successStatusVTPM("template deleted successfully"),
	}, nil
}

// ListTemplates lists all templates.
func (s *VTPMGRPCService) ListTemplates(
	ctx context.Context,
	req *platformv1.ListTemplatesRequest,
) (*platformv1.ListTemplatesResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	templates, err := s.service.ListTemplates(ctx)
	if err != nil {
		return nil, s.mapError("ListTemplates", err)
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
func (s *VTPMGRPCService) CloneTemplate(
	ctx context.Context,
	req *platformv1.CloneTemplateRequest,
) (*platformv1.CloneTemplateResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetOptions() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingCloneOptions{}.Error())
	}

	opts := s.protoToCloneOptions(req.GetOptions())

	bundle, err := s.service.CloneTemplate(ctx, opts)
	if err != nil {
		return nil, s.mapError("CloneTemplate", err)
	}

	return &platformv1.CloneTemplateResponse{
		Status: successStatusVTPM("template cloned successfully"),
		Bundle: s.bundleToProto(bundle),
	}, nil
}

// ExportBundle exports a bundle to a tar.gz archive.
func (s *VTPMGRPCService) ExportBundle(
	req *platformv1.ExportBundleRequest,
	stream grpc.ServerStreamingServer[platformv1.ExportBundleResponse],
) error {

	if s.service == nil {
		return status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetId() == "" {
		return status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	// Create a buffer to hold the exported data
	var buf bytes.Buffer

	err := s.service.ExportBundle(stream.Context(), req.GetId(), &buf)
	if err != nil {
		return s.mapError("ExportBundle", err)
	}

	// Stream the data in chunks
	data := buf.Bytes()
	for i := 0; i < len(data); i += vtpmExportChunkSize {
		end := i + vtpmExportChunkSize
		if end > len(data) {
			end = len(data)
		}

		err := stream.Send(&platformv1.ExportBundleResponse{
			Data: data[i:end],
		})
		if err != nil {
			s.logger.Error(err, "ExportBundle stream send failed", "operation", "ExportBundle")
			return status.Error(codes.Internal, ErrStreamSendFailed{Operation: "ExportBundle", Cause: err}.Error())
		}
	}

	return nil
}

// ImportBundle imports a bundle from a tar.gz archive.
func (s *VTPMGRPCService) ImportBundle(
	stream grpc.ClientStreamingServer[platformv1.ImportBundleRequest, platformv1.ImportBundleResponse],
) error {

	if s.service == nil {
		return status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	// Collect all chunks
	var buf bytes.Buffer

	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.logger.Error(err, "ImportBundle stream recv failed", "operation", "ImportBundle")
			return status.Error(codes.Internal, ErrStreamRecvFailed{Operation: "ImportBundle", Cause: err}.Error())
		}

		_, err = buf.Write(chunk.GetData())
		if err != nil {
			s.logger.Error(err, "ImportBundle buffer write failed", "operation", "ImportBundle")
			return status.Error(codes.Internal, "failed to buffer import data")
		}
	}

	bundle, err := s.service.ImportBundle(stream.Context(), &buf)
	if err != nil {
		return s.mapError("ImportBundle", err)
	}

	return stream.SendAndClose(&platformv1.ImportBundleResponse{
		Status: successStatusVTPM("bundle imported successfully"),
		Bundle: s.bundleToProto(bundle),
	})
}

// ValidateBundle validates bundle integrity.
func (s *VTPMGRPCService) ValidateBundle(
	ctx context.Context,
	req *platformv1.ValidateBundleRequest,
) (*platformv1.ValidateBundleResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
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
		Status: successStatusVTPM("bundle is valid"),
		Valid:  true,
		Errors: nil,
	}, nil
}

// GetBundlePath returns the filesystem path to a bundle.
func (s *VTPMGRPCService) GetBundlePath(
	ctx context.Context,
	req *platformv1.GetBundlePathRequest,
) (*platformv1.GetBundlePathResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	path := s.service.GetBundlePath(req.GetId())

	return &platformv1.GetBundlePathResponse{
		Path: path,
	}, nil
}

// GetTPMSocketPath returns the TPM socket path for a bundle.
func (s *VTPMGRPCService) GetTPMSocketPath(
	ctx context.Context,
	req *platformv1.GetTPMSocketPathRequest,
) (*platformv1.GetTPMSocketPathResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	path := s.service.GetTPMSocketPath(req.GetId())

	return &platformv1.GetTPMSocketPathResponse{
		Path: path,
	}, nil
}

// GetNVRAMPath returns the OVMF NVRAM path for a bundle.
func (s *VTPMGRPCService) GetNVRAMPath(
	ctx context.Context,
	req *platformv1.GetNVRAMPathRequest,
) (*platformv1.GetNVRAMPathResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	path := s.service.GetNVRAMPath(req.GetId())

	return &platformv1.GetNVRAMPathResponse{
		Path: path,
	}, nil
}

// =============================================================================
// Runtime TPM Operations
// =============================================================================

// StartVTPM starts the swtpm daemon for a bundle.
func (s *VTPMGRPCService) StartVTPM(
	ctx context.Context,
	req *platformv1.StartVTPMRequest,
) (*platformv1.StartVTPMResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	err := s.service.Start(ctx, req.GetBundleId())
	if err != nil {
		return nil, s.mapError("StartVTPM", err)
	}

	socketPath := s.service.GetTPMSocketPath(req.GetBundleId())

	return &platformv1.StartVTPMResponse{
		Status:     successStatusVTPM("vtpm started successfully"),
		BundleId:   req.GetBundleId(),
		Running:    true,
		SocketPath: socketPath,
	}, nil
}

// StopVTPM stops the swtpm daemon for a bundle.
func (s *VTPMGRPCService) StopVTPM(
	ctx context.Context,
	req *platformv1.StopVTPMRequest,
) (*platformv1.StopVTPMResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	err := s.service.Stop(ctx, req.GetBundleId())
	if err != nil {
		return nil, s.mapError("StopVTPM", err)
	}

	return &platformv1.StopVTPMResponse{
		Status:   successStatusVTPM("vtpm stopped successfully"),
		BundleId: req.GetBundleId(),
		Stopped:  true,
	}, nil
}

// IsVTPMRunning checks if the vTPM for a bundle is running.
func (s *VTPMGRPCService) IsVTPMRunning(
	ctx context.Context,
	req *platformv1.IsVTPMRunningRequest,
) (*platformv1.IsVTPMRunningResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	running := s.service.IsRunning(req.GetBundleId())

	return &platformv1.IsVTPMRunningResponse{
		BundleId: req.GetBundleId(),
		Running:  running,
	}, nil
}

// QuoteVTPM generates a TPM quote over specified PCRs.
func (s *VTPMGRPCService) QuoteVTPM(
	ctx context.Context,
	req *platformv1.QuoteVTPMRequest,
) (*platformv1.QuoteVTPMResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	if len(req.GetNonce()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingNonce{}.Error())
	}

	if len(req.GetPcrs()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPCRs{}.Error())
	}

	// Convert int32 PCR indices to int
	pcrs := make([]int, 0, len(req.GetPcrs()))
	for _, p := range req.GetPcrs() {
		pcrs = append(pcrs, int(p))
	}

	result, err := s.service.Quote(ctx, req.GetBundleId(), req.GetNonce(), pcrs)
	if err != nil {
		return nil, s.mapError("QuoteVTPM", err)
	}

	// Convert map[int][]byte to map[int32][]byte for proto
	pcrValues := make(map[int32][]byte, len(result.PCRValues))
	for k, v := range result.PCRValues {
		pcrValues[int32(k)] = v
	}

	return &platformv1.QuoteVTPMResponse{
		Status:        successStatusVTPM("quote generated successfully"),
		BundleId:      req.GetBundleId(),
		Quote:         result.Quote,
		Signature:     result.Signature,
		PcrValues:     pcrValues,
		HashAlgorithm: result.HashAlgorithm,
	}, nil
}

// SealVTPM encrypts data to the TPM, optionally binding to PCR values.
func (s *VTPMGRPCService) SealVTPM(
	ctx context.Context,
	req *platformv1.SealVTPMRequest,
) (*platformv1.SealVTPMResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	if len(req.GetData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingSealData{}.Error())
	}

	// Convert int32 PCR indices to int
	pcrs := make([]int, 0, len(req.GetPcrs()))
	for _, p := range req.GetPcrs() {
		pcrs = append(pcrs, int(p))
	}

	sealOpts := &vtpm.SealOptions{
		PCRs:      pcrs,
		AuthValue: req.GetAuthValue(),
	}

	sealedData, err := s.service.Seal(ctx, req.GetBundleId(), req.GetData(), sealOpts)
	if err != nil {
		return nil, s.mapError("SealVTPM", err)
	}

	return &platformv1.SealVTPMResponse{
		Status:     successStatusVTPM("data sealed successfully"),
		BundleId:   req.GetBundleId(),
		SealedData: sealedData,
	}, nil
}

// UnsealVTPM decrypts data that was previously sealed to the TPM.
func (s *VTPMGRPCService) UnsealVTPM(
	ctx context.Context,
	req *platformv1.UnsealVTPMRequest,
) (*platformv1.UnsealVTPMResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	if len(req.GetSealedData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingSealedData{}.Error())
	}

	data, err := s.service.Unseal(ctx, req.GetBundleId(), req.GetSealedData(), req.GetAuthValue())
	if err != nil {
		return nil, s.mapError("UnsealVTPM", err)
	}

	return &platformv1.UnsealVTPMResponse{
		Status:   successStatusVTPM("data unsealed successfully"),
		BundleId: req.GetBundleId(),
		Data:     data,
	}, nil
}

// ExtendVTPMPCR extends a PCR with the provided data.
func (s *VTPMGRPCService) ExtendVTPMPCR(
	ctx context.Context,
	req *platformv1.ExtendVTPMPCRRequest,
) (*platformv1.ExtendVTPMPCRResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	if len(req.GetData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingExtendData{}.Error())
	}

	err := s.service.ExtendPCR(ctx, req.GetBundleId(), int(req.GetPcrIndex()), req.GetData())
	if err != nil {
		return nil, s.mapError("ExtendVTPMPCR", err)
	}

	return &platformv1.ExtendVTPMPCRResponse{
		Status:   successStatusVTPM("pcr extended successfully"),
		BundleId: req.GetBundleId(),
		PcrIndex: req.GetPcrIndex(),
		Extended: true,
	}, nil
}

// ReadVTPMPCR reads the current value of a PCR.
func (s *VTPMGRPCService) ReadVTPMPCR(
	ctx context.Context,
	req *platformv1.ReadVTPMPCRRequest,
) (*platformv1.ReadVTPMPCRResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilVTPMService{}.Error())
	}

	if req.GetBundleId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBundleID{}.Error())
	}

	value, err := s.service.ReadPCR(ctx, req.GetBundleId(), int(req.GetPcrIndex()))
	if err != nil {
		return nil, s.mapError("ReadVTPMPCR", err)
	}

	return &platformv1.ReadVTPMPCRResponse{
		Status:   successStatusVTPM("pcr read successfully"),
		BundleId: req.GetBundleId(),
		PcrIndex: req.GetPcrIndex(),
		Value:    value,
	}, nil
}

// Conversion helpers: proto to service types

func (s *VTPMGRPCService) protoToCreateBundleOptions(opts *platformv1.CreateBundleOptions) *vtpm.CreateBundleOptions {
	return &vtpm.CreateBundleOptions{
		Mode:              s.protoToBundleMode(opts.GetMode()),
		Hostname:          opts.GetHostname(),
		EKAlgorithm:       s.protoToEKAlgorithm(opts.GetEkAlgorithm()),
		SecureBootEnabled: opts.GetSecureBootEnabled(),
		Labels:            opts.GetLabels(),
		TemplateID:        opts.GetTemplateId(),
	}
}

func (s *VTPMGRPCService) protoToCreateTemplateOptions(opts *platformv1.CreateTemplateOptions) *vtpm.CreateTemplateOptions {
	return &vtpm.CreateTemplateOptions{
		ID:                opts.GetId(),
		Description:       opts.GetDescription(),
		EKAlgorithm:       s.protoToEKAlgorithm(opts.GetEkAlgorithm()),
		SecureBootEnabled: opts.GetSecureBootEnabled(),
	}
}

func (s *VTPMGRPCService) protoToCloneOptions(opts *platformv1.CloneOptions) *vtpm.CloneOptions {
	return &vtpm.CloneOptions{
		TemplateID: opts.GetTemplateId(),
		Hostname:   opts.GetHostname(),
		Labels:     opts.GetLabels(),
	}
}

func (s *VTPMGRPCService) protoToListOptions(opts *platformv1.ListBundleOptions) *vtpm.ListOptions {
	if opts == nil {
		return nil
	}
	return &vtpm.ListOptions{
		Mode:   s.protoToBundleMode(opts.GetMode()),
		Labels: opts.GetLabels(),
		Limit:  int(opts.GetLimit()),
		Offset: int(opts.GetOffset()),
	}
}

func (s *VTPMGRPCService) protoToBundleMode(mode platformv1.BundleMode) vtpm.BundleMode {
	switch mode {
	case platformv1.BundleMode_BUNDLE_MODE_TEMPLATE:
		return vtpm.BundleModeTemplate
	case platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED:
		return vtpm.BundleModePreAssigned
	default:
		return ""
	}
}

func (s *VTPMGRPCService) protoToEKAlgorithm(alg platformv1.EKAlgorithm) vtpm.EKAlgorithm {
	switch alg {
	case platformv1.EKAlgorithm_EK_ALGORITHM_RSA:
		return vtpm.EKAlgorithmRSA
	case platformv1.EKAlgorithm_EK_ALGORITHM_ECC:
		return vtpm.EKAlgorithmECC
	default:
		return vtpm.EKAlgorithmRSA
	}
}

// Conversion helpers: service types to proto

func (s *VTPMGRPCService) bundleToProto(bundle *vtpm.Bundle) *platformv1.Bundle {
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

func (s *VTPMGRPCService) templateToProto(template *vtpm.Template) *platformv1.Template {
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

func (s *VTPMGRPCService) manifestToProto(manifest *vtpm.Manifest) *platformv1.Manifest {
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
	}

	if manifest.EKCertificate != nil {
		pb.EkCertificate = s.ekCertInfoToProto(manifest.EKCertificate)
	}

	if manifest.SecureBootKeys != nil {
		pb.SecureBootKeys = s.secureBootKeyInfoToProto(manifest.SecureBootKeys)
	}

	return pb
}

func (s *VTPMGRPCService) ekCertInfoToProto(info *vtpm.EKCertInfo) *platformv1.EKCertInfo {
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

func (s *VTPMGRPCService) secureBootKeyInfoToProto(info *vtpm.SecureBootKeyInfo) *platformv1.SecureBootKeyInfo {
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

func (s *VTPMGRPCService) secureBootKeyPathsToProto(paths *vtpm.SecureBootKeyPaths) *platformv1.SecureBootKeyPaths {
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

func (s *VTPMGRPCService) tpmStateToProto(state *vtpm.TPMState) *platformv1.TPMState {
	if state == nil {
		return nil
	}

	return &platformv1.TPMState{
		StateDir:     state.StateDir,
		PermallFile:  state.PermallFile,
		VolatileFile: state.VolatileFile,
	}
}

func (s *VTPMGRPCService) ovmfStateToProto(state *vtpm.OVMFState) *platformv1.OVMFState {
	if state == nil {
		return nil
	}

	return &platformv1.OVMFState{
		NvramFile: state.NVRAMFile,
	}
}

func (s *VTPMGRPCService) bundleModeToProto(mode vtpm.BundleMode) platformv1.BundleMode {
	switch mode {
	case vtpm.BundleModeTemplate:
		return platformv1.BundleMode_BUNDLE_MODE_TEMPLATE
	case vtpm.BundleModePreAssigned:
		return platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED
	default:
		return platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED
	}
}

func (s *VTPMGRPCService) ekAlgorithmToProto(alg vtpm.EKAlgorithm) platformv1.EKAlgorithm {
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
func (s *VTPMGRPCService) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "vtpm operation failed", "operation", operation)

	// Check for specific error types and map to appropriate gRPC codes
	errMsg := err.Error()

	// Check for not found errors
	if containsAnyVTPM(errMsg, "not found", "does not exist", "no such") {
		return status.Error(codes.NotFound, errMsg)
	}

	// Check for already exists errors
	if containsAnyVTPM(errMsg, "already exists", "duplicate") {
		return status.Error(codes.AlreadyExists, errMsg)
	}

	// Check for invalid argument errors
	if containsAnyVTPM(errMsg, "invalid", "required", "must be", "cannot be") {
		return status.Error(codes.InvalidArgument, errMsg)
	}

	// Check for permission errors
	if containsAnyVTPM(errMsg, "permission", "denied", "unauthorized", "forbidden") {
		return status.Error(codes.PermissionDenied, errMsg)
	}

	// Check for not running errors (vTPM must be started first)
	if containsAnyVTPM(errMsg, "not running", "not started") {
		return status.Error(codes.FailedPrecondition, errMsg)
	}

	// Default to internal error
	return status.Error(codes.Internal, errMsg)
}

// containsAnyVTPM checks if the string contains any of the substrings.
func containsAnyVTPM(s string, substrings ...string) bool {
	lowered := strings.ToLower(s)
	for _, sub := range substrings {
		if strings.Contains(lowered, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// successStatusVTPM creates a success status message.
func successStatusVTPM(message string) *platformv1.Status {
	return &platformv1.Status{
		Success: true,
		Message: message,
	}
}

// Ensure VTPMGRPCService implements the VTPMServiceServer interface.
var _ platformv1.VTPMServiceServer = (*VTPMGRPCService)(nil)
