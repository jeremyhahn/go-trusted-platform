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
	"encoding/json"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// pollSessionPendingStatus is the pending-status string returned by PollSession
// when a session has not been fulfilled yet, matching the REST
// PollPendingResponse{Status: "pending"} body.
const pollSessionPendingStatus = "pending"

// fulfillSessionStatus is the acknowledgement status returned by
// FulfillSession, matching the REST {"status": "fulfilled"} body.
const fulfillSessionStatus = "fulfilled"

// ConfigDeliveryGRPCService implements the platform.v1 ConfigDeliveryService
// backed by the pre-enrollment config delivery service
// (*configdelivery.Service). Authentication (single-use nonce + EAB HMAC and
// EK-certificate binding) is enforced inside the backing service, so this
// surface only binds the wire protocol and maps typed service errors to gRPC
// status codes with the same semantics as the REST handler.
type ConfigDeliveryGRPCService struct {
	platformv1.UnimplementedConfigDeliveryServiceServer

	service *configdelivery.Service
	// conv reuses the canonical entities.DeviceProfile <-> platform.v1
	// DeviceProfile converters owned by DeviceGRPCService (DRY: there is
	// exactly one profile converter in this package).
	conv   *DeviceGRPCService
	logger *slog.Logger
}

// NewConfigDeliveryGRPCService creates a new ConfigDeliveryGRPCService. The
// backing service may be nil when the provisioning dependencies are not
// configured; every RPC then returns a typed Unavailable error via the
// requireService guard instead of panicking.
func NewConfigDeliveryGRPCService(service *configdelivery.Service, logger *slog.Logger) *ConfigDeliveryGRPCService {
	if logger == nil {
		logger = slog.Default()
	}
	return &ConfigDeliveryGRPCService{
		service: service,
		conv:    NewDeviceGRPCService(nil, nil, logger),
		logger:  logger,
	}
}

// requireService returns a typed Unavailable error when the backing config
// delivery service is not configured.
func (s *ConfigDeliveryGRPCService) requireService() error {
	if s.service == nil {
		return status.Error(codes.Unavailable, ErrConfigDeliveryServiceNotAvailable{}.Error())
	}
	return nil
}

// GetNonce issues a new single-use nonce for replay prevention.
func (s *ConfigDeliveryGRPCService) GetNonce(
	ctx context.Context,
	req *platformv1.GetNonceRequest,
) (*platformv1.GetNonceResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	nonce, err := s.service.IssueNonce()
	if err != nil {
		s.logger.Error("configdelivery grpc: failed to issue nonce", "error", err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &platformv1.GetNonceResponse{Nonce: nonce}, nil
}

// FetchConfig authenticates a device and resolves its platform configuration.
// The tri-state result maps onto the response oneof: delivered config XOR
// pending session; errors surface as gRPC status codes.
func (s *ConfigDeliveryGRPCService) FetchConfig(
	ctx context.Context,
	req *platformv1.FetchConfigRequest,
) (*platformv1.FetchConfigResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	configResp, pendingResp, err := s.service.ResolveConfig(ctx, pbToConfigDeliveryRequest(req))
	if err != nil {
		return nil, configDeliveryErrorToStatus(err, fetchConfigErrorMatchers)
	}

	if pendingResp != nil {
		return &platformv1.FetchConfigResponse{
			Result: &platformv1.FetchConfigResponse_Pending{
				Pending: pendingResponseToPb(pendingResp),
			},
		}, nil
	}

	delivered, err := configResponseToDelivered(configResp)
	if err != nil {
		s.logger.Error("configdelivery grpc: config serialization failed", "error", err)
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &platformv1.FetchConfigResponse{
		Result: &platformv1.FetchConfigResponse_Delivered{Delivered: delivered},
	}, nil
}

// SignDigest authenticates a remote resign request and signs the supplied UKI
// (or kernel-module) digest with the control-plane Secure Boot DB key.
func (s *ConfigDeliveryGRPCService) SignDigest(
	ctx context.Context,
	req *platformv1.SignDigestRequest,
) (*platformv1.SignDigestResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	resp, err := s.service.SignDigest(ctx, pbToSignRequest(req))
	if err != nil {
		return nil, configDeliveryErrorToStatus(err, signDigestErrorMatchers)
	}

	return &platformv1.SignDigestResponse{
		Signature: resp.Signature,
		CertPem:   resp.CertPEM,
	}, nil
}

// PollSession checks whether a pending provisioning session has been
// fulfilled, returning either the delivered config or a pending status.
func (s *ConfigDeliveryGRPCService) PollSession(
	ctx context.Context,
	req *platformv1.PollSessionRequest,
) (*platformv1.PollSessionResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument,
			configdelivery.ErrInvalidRequest{Reason: "session_id is required"}.Error())
	}

	configResp, err := s.service.PollSession(ctx, req.GetSessionId())
	if err != nil {
		return nil, configDeliveryErrorToStatus(err, sessionErrorMatchers)
	}

	if configResp == nil {
		return &platformv1.PollSessionResponse{
			Result: &platformv1.PollSessionResponse_PendingStatus{
				PendingStatus: pollSessionPendingStatus,
			},
		}, nil
	}

	delivered, err := configResponseToDelivered(configResp)
	if err != nil {
		s.logger.Error("configdelivery grpc: config serialization failed", "error", err)
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &platformv1.PollSessionResponse{
		Result: &platformv1.PollSessionResponse_Delivered{Delivered: delivered},
	}, nil
}

// FulfillSession links a device profile to a pending provisioning session.
func (s *ConfigDeliveryGRPCService) FulfillSession(
	ctx context.Context,
	req *platformv1.FulfillSessionRequest,
) (*platformv1.FulfillSessionResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument,
			configdelivery.ErrInvalidRequest{Reason: "session_id is required"}.Error())
	}

	if err := s.service.FulfillSession(ctx, req.GetSessionId(), req.GetProfileId()); err != nil {
		return nil, configDeliveryErrorToStatus(err, sessionErrorMatchers)
	}

	return &platformv1.FulfillSessionResponse{Status: fulfillSessionStatus}, nil
}

// ListSessions returns all active (non-expired) provisioning sessions.
func (s *ConfigDeliveryGRPCService) ListSessions(
	ctx context.Context,
	req *platformv1.ListSessionsRequest,
) (*platformv1.ListSessionsResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	sessions := s.service.ListSessions()
	pbSessions := make([]*platformv1.ProvisioningSession, 0, len(sessions))
	for _, session := range sessions {
		pbSessions = append(pbSessions, s.sessionToPb(session))
	}

	return &platformv1.ListSessionsResponse{Sessions: pbSessions}, nil
}

// GetSession returns a provisioning session by ID.
func (s *ConfigDeliveryGRPCService) GetSession(
	ctx context.Context,
	req *platformv1.GetSessionRequest,
) (*platformv1.GetSessionResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument,
			configdelivery.ErrInvalidRequest{Reason: "session_id is required"}.Error())
	}

	session, err := s.service.GetSession(req.GetSessionId())
	if err != nil {
		return nil, configDeliveryErrorToStatus(err, sessionErrorMatchers)
	}

	return &platformv1.GetSessionResponse{Session: s.sessionToPb(session)}, nil
}

// pbToConfigDeliveryRequest maps a FetchConfigRequest protobuf message to the
// configdelivery domain request.
func pbToConfigDeliveryRequest(pb *platformv1.FetchConfigRequest) *configdelivery.ConfigRequest {
	if pb == nil {
		return &configdelivery.ConfigRequest{}
	}
	return &configdelivery.ConfigRequest{
		EKSerial:   pb.GetEkSerial(),
		MACAddress: pb.GetMacAddress(),
		EKCert:     pb.GetEkCert(),
		EABKeyID:   pb.GetEabKeyId(),
		EABHMAC:    pb.GetEabHmac(),
		Nonce:      pb.GetNonce(),
	}
}

// pbToSignRequest maps a SignDigestRequest protobuf message to the
// configdelivery domain request.
func pbToSignRequest(pb *platformv1.SignDigestRequest) *configdelivery.SignRequest {
	if pb == nil {
		return &configdelivery.SignRequest{}
	}
	return &configdelivery.SignRequest{
		EKSerial:   pb.GetEkSerial(),
		MACAddress: pb.GetMacAddress(),
		EKCert:     pb.GetEkCert(),
		EABKeyID:   pb.GetEabKeyId(),
		EABHMAC:    pb.GetEabHmac(),
		Nonce:      pb.GetNonce(),
		Digest:     pb.GetDigest(),
		KeyRef:     pb.GetKeyRef(),
	}
}

// pendingResponseToPb maps a configdelivery PendingResponse to its protobuf
// representation.
func pendingResponseToPb(p *configdelivery.PendingResponse) *platformv1.PendingSession {
	if p == nil {
		return nil
	}
	return &platformv1.PendingSession{
		SessionId:           p.SessionID,
		ProvisionUrl:        p.ProvisionURL,
		PollIntervalSeconds: int32(p.PollInterval),
	}
}

// configResponseToDelivered maps a configdelivery ConfigResponse to the
// DeliveredConfig protobuf message, carrying the merged device config as its
// JSON encoding (config_json), matching the REST ConfigResponse.config field.
func configResponseToDelivered(resp *configdelivery.ConfigResponse) (*platformv1.DeliveredConfig, error) {
	if resp == nil {
		return nil, ErrConfigSerializationFailed{Cause: errors.New("nil config response")}
	}
	configJSON, err := json.Marshal(resp.Config)
	if err != nil {
		return nil, ErrConfigSerializationFailed{Cause: err}
	}
	return &platformv1.DeliveredConfig{
		ConfigJson: configJSON,
		Status:     resp.Status,
	}, nil
}

// sessionToPb maps a configdelivery Session to its protobuf representation,
// reusing the canonical DeviceProfile converter for the embedded profile.
func (s *ConfigDeliveryGRPCService) sessionToPb(session *configdelivery.Session) *platformv1.ProvisioningSession {
	if session == nil {
		return nil
	}
	pb := &platformv1.ProvisioningSession{
		Id:         session.ID,
		EkSerial:   session.EKSerial,
		MacAddress: session.MACAddress,
		TenantId:   session.TenantID,
		ProfileId:  session.ProfileID.Uint64(),
		Profile:    s.conv.profileToPb(session.Profile),
		Fulfilled:  session.Fulfilled,
	}
	if !session.CreatedAt.IsZero() {
		pb.CreatedAt = timestamppb.New(session.CreatedAt)
	}
	if !session.ExpiresAt.IsZero() {
		pb.ExpiresAt = timestamppb.New(session.ExpiresAt)
	}
	return pb
}

// configDeliveryErrorMatcher reports whether an error matches a known
// configdelivery error type and, if so, which gRPC status code applies.
type configDeliveryErrorMatcher func(error) (codes.Code, bool)

// matchConfigDeliveryError builds a matcher binding the typed configdelivery
// error T to the given gRPC status code via errors.As.
func matchConfigDeliveryError[T error](code codes.Code) configDeliveryErrorMatcher {
	return func(err error) (codes.Code, bool) {
		var target T
		if errors.As(err, &target) {
			return code, true
		}
		return codes.OK, false
	}
}

// fetchConfigErrorMatchers mirrors handler.go writeFetchConfigError:
// 400 -> InvalidArgument, 401 -> Unauthenticated, 403 -> PermissionDenied.
// Ordered; first match wins.
var fetchConfigErrorMatchers = []configDeliveryErrorMatcher{
	matchConfigDeliveryError[configdelivery.ErrInvalidRequest](codes.InvalidArgument),
	matchConfigDeliveryError[configdelivery.ErrNonceRequired](codes.InvalidArgument),
	matchConfigDeliveryError[configdelivery.ErrNonceExpired](codes.InvalidArgument),
	matchConfigDeliveryError[configdelivery.ErrEABValidationFailed](codes.Unauthenticated),
	matchConfigDeliveryError[configdelivery.ErrEKCertParseFailed](codes.InvalidArgument),
	matchConfigDeliveryError[configdelivery.ErrEKCertRequired](codes.PermissionDenied),
	matchConfigDeliveryError[configdelivery.ErrEKCertMismatch](codes.PermissionDenied),
}

// signDigestErrorMatchers mirrors handler.go writeSignError:
// 400 -> InvalidArgument, 403 -> PermissionDenied, 409 -> FailedPrecondition,
// 503 -> Unavailable. Ordered; first match wins.
var signDigestErrorMatchers = []configDeliveryErrorMatcher{
	matchConfigDeliveryError[configdelivery.ErrInvalidRequest](codes.InvalidArgument),
	matchConfigDeliveryError[configdelivery.ErrNonceRequired](codes.InvalidArgument),
	matchConfigDeliveryError[configdelivery.ErrNonceExpired](codes.InvalidArgument),
	matchConfigDeliveryError[configdelivery.ErrEKCertParseFailed](codes.InvalidArgument),
	matchConfigDeliveryError[configdelivery.ErrEABValidationFailed](codes.PermissionDenied),
	matchConfigDeliveryError[configdelivery.ErrEKCertRequired](codes.PermissionDenied),
	matchConfigDeliveryError[configdelivery.ErrEKCertMismatch](codes.PermissionDenied),
	matchConfigDeliveryError[configdelivery.ErrRemoteSignNotConfigured](codes.FailedPrecondition),
	matchConfigDeliveryError[configdelivery.ErrSignerUnavailable](codes.Unavailable),
	matchConfigDeliveryError[configdelivery.ErrMissingProfileService](codes.Unavailable),
}

// sessionErrorMatchers mirrors handler.go writeSessionError:
// 404 -> NotFound, 400 -> InvalidArgument. Ordered; first match wins.
var sessionErrorMatchers = []configDeliveryErrorMatcher{
	matchConfigDeliveryError[configdelivery.ErrSessionNotFound](codes.NotFound),
	matchConfigDeliveryError[configdelivery.ErrProfileNotFound](codes.NotFound),
	matchConfigDeliveryError[configdelivery.ErrSessionExpired](codes.InvalidArgument),
	matchConfigDeliveryError[configdelivery.ErrSessionAlreadyFulfilled](codes.InvalidArgument),
	// A session fulfilled without a resolved profile is an invalid
	// server-side state (REST 500) -> Internal, pinned explicitly.
	matchConfigDeliveryError[configdelivery.ErrSessionProfileMissing](codes.Internal),
}

// configDeliveryErrorToStatus maps a typed configdelivery error to a gRPC
// status using the supplied ordered matcher table; unknown errors map to
// Internal (the REST handler's 500 default).
func configDeliveryErrorToStatus(err error, matchers []configDeliveryErrorMatcher) error {
	for _, match := range matchers {
		if code, ok := match(err); ok {
			return status.Error(code, err.Error())
		}
	}
	return status.Error(codes.Internal, err.Error())
}

// Ensure ConfigDeliveryGRPCService implements the generated server interface.
var _ platformv1.ConfigDeliveryServiceServer = (*ConfigDeliveryGRPCService)(nil)
