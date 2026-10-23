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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CeremonyGRPCService implements the Ceremony gRPC service.
type CeremonyGRPCService struct {
	platformv1.UnimplementedCeremonyServiceServer

	logger  *logging.Logger
	service *CeremonyService
}

// NewCeremonyGRPCService constructs a new Ceremony gRPC service.
func NewCeremonyGRPCService(logger *logging.Logger, svc *CeremonyService) *CeremonyGRPCService {
	return &CeremonyGRPCService{logger: logger, service: svc}
}

// ceremonyAuthenticatorToService maps a proto authenticator type to the
// service-layer value.
var ceremonyAuthenticatorToService = map[platformv1.CeremonyAuthenticatorType]CeremonyAuthenticatorType{
	platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_UNSPECIFIED: CeremonyAuthenticatorUnspecified,
	platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_PIV:         CeremonyAuthenticatorPIV,
	platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_FIDO2:       CeremonyAuthenticatorFIDO2,
	platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_SOFTWARE:    CeremonyAuthenticatorSoftware,
}

// ceremonyRoleToService maps a proto role to the service-layer value.
var ceremonyRoleToService = map[platformv1.CeremonyOfficerRole]CeremonyOfficerRole{
	platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_UNSPECIFIED: CeremonyRoleUnspecified,
	platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_SO:          CeremonyRoleSO,
	platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN:       CeremonyRoleAdmin,
	platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_USER:        CeremonyRoleUser,
}

// ceremonyStateToProto maps a service-layer state to a proto enum.
var ceremonyStateToProto = map[CeremonyStateValue]platformv1.CeremonyState{
	CeremonyStateUnknown:       platformv1.CeremonyState_CEREMONY_STATE_UNSPECIFIED,
	CeremonyStateUninitialized: platformv1.CeremonyState_CEREMONY_STATE_UNINITIALIZED,
	CeremonyStateInProgress:    platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS,
	CeremonyStateComplete:      platformv1.CeremonyState_CEREMONY_STATE_COMPLETE,
}

// ceremonyErrorToGRPC translates ceremony service errors to gRPC status.
func ceremonyErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrCeremonyNotConfigured):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, ErrCeremonyOfficerRequired),
		errors.Is(err, ErrCeremonyChallengeRequired),
		errors.Is(err, ErrCeremonyCSRRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// Init implements platformv1.CeremonyServiceServer.
func (s *CeremonyGRPCService) Init(ctx context.Context, req *platformv1.CeremonyInitRequest) (*platformv1.CeremonyInitResponse, error) {
	in := &CeremonyInitRequest{
		SOPIN:                  req.GetSoPin(),
		UserPIN:                req.GetUserPin(),
		Threshold:              req.GetThreshold(),
		Hostname:               req.GetHostname(),
		SANs:                   req.GetSans(),
		CredentialSealStrategy: req.GetCredentialSealStrategy(),
	}
	out, err := s.service.Init(ctx, in)
	if err != nil {
		return nil, ceremonyErrorToGRPC(err)
	}
	resp := &platformv1.CeremonyInitResponse{
		CeremonyId:   out.CeremonyID,
		State:        ceremonyStateToProto[out.State],
		AdminCertPem: out.AdminCertPEM,
		AdminKeyPem:  out.AdminKeyPEM,
		SpkiPin:      out.SPKIPin,
	}
	if !out.InitializedAt.IsZero() {
		resp.InitializedAt = timestamppb.New(out.InitializedAt)
	}
	return resp, nil
}

// Status implements platformv1.CeremonyServiceServer.
func (s *CeremonyGRPCService) Status(ctx context.Context, _ *platformv1.CeremonyStatusRequest) (*platformv1.CeremonyStatusResponse, error) {
	out, err := s.service.Status(ctx)
	if err != nil {
		return nil, ceremonyErrorToGRPC(err)
	}
	resp := &platformv1.CeremonyStatusResponse{
		CeremonyId:       out.CeremonyID,
		State:            ceremonyStateToProto[out.State],
		Threshold:        out.Threshold,
		OfficersEnrolled: out.OfficersEnrolled,
		OfficersRequired: out.OfficersRequired,
	}
	if !out.InitializedAt.IsZero() {
		resp.InitializedAt = timestamppb.New(out.InitializedAt)
	}
	return resp, nil
}

// ClaimCertBegin implements platformv1.CeremonyServiceServer.
func (s *CeremonyGRPCService) ClaimCertBegin(ctx context.Context, req *platformv1.CeremonyClaimCertBeginRequest) (*platformv1.CeremonyClaimCertBeginResponse, error) {
	in := &CeremonyClaimCertBeginRequest{
		Username:          req.GetUsername(),
		AuthenticatorType: ceremonyAuthenticatorToService[req.GetAuthenticatorType()],
		Slot:              req.GetSlot(),
		CredentialID:      req.GetCredentialId(),
	}
	out, err := s.service.ClaimCertBegin(ctx, in)
	if err != nil {
		return nil, ceremonyErrorToGRPC(err)
	}
	resp := &platformv1.CeremonyClaimCertBeginResponse{
		Nonce:       out.Nonce,
		ChallengeId: out.ChallengeID,
	}
	if !out.ExpiresAt.IsZero() {
		resp.ExpiresAt = timestamppb.New(out.ExpiresAt)
	}
	return resp, nil
}

// ClaimCertComplete implements platformv1.CeremonyServiceServer.
func (s *CeremonyGRPCService) ClaimCertComplete(ctx context.Context, req *platformv1.CeremonyClaimCertCompleteRequest) (*platformv1.CeremonyClaimCertCompleteResponse, error) {
	in := &CeremonyClaimCertCompleteRequest{
		Username:  req.GetUsername(),
		Nonce:     req.GetNonce(),
		Signature: req.GetSignature(),
	}
	out, err := s.service.ClaimCertComplete(ctx, in)
	if err != nil {
		return nil, ceremonyErrorToGRPC(err)
	}
	return &platformv1.CeremonyClaimCertCompleteResponse{
		CertificatePem: out.CertificatePEM,
		ChainPem:       out.ChainPEM,
	}, nil
}

// ClaimShareBegin implements platformv1.CeremonyServiceServer.
func (s *CeremonyGRPCService) ClaimShareBegin(ctx context.Context, req *platformv1.CeremonyClaimShareBeginRequest) (*platformv1.CeremonyClaimShareBeginResponse, error) {
	out, err := s.service.ClaimShareBegin(ctx, &CeremonyClaimShareBeginRequest{
		Username: req.GetUsername(),
	})
	if err != nil {
		return nil, ceremonyErrorToGRPC(err)
	}
	resp := &platformv1.CeremonyClaimShareBeginResponse{
		Nonce: out.Nonce,
	}
	if !out.ExpiresAt.IsZero() {
		resp.ExpiresAt = timestamppb.New(out.ExpiresAt)
	}
	return resp, nil
}

// ClaimShareComplete implements platformv1.CeremonyServiceServer.
func (s *CeremonyGRPCService) ClaimShareComplete(ctx context.Context, req *platformv1.CeremonyClaimShareCompleteRequest) (*platformv1.CeremonyClaimShareCompleteResponse, error) {
	out, err := s.service.ClaimShareComplete(ctx, &CeremonyClaimShareCompleteRequest{
		Username:  req.GetUsername(),
		Nonce:     req.GetNonce(),
		Signature: req.GetSignature(),
	})
	if err != nil {
		return nil, ceremonyErrorToGRPC(err)
	}
	return &platformv1.CeremonyClaimShareCompleteResponse{
		Share: out.Share,
		Index: out.Index,
	}, nil
}

// SignCSR implements platformv1.CeremonyServiceServer.
func (s *CeremonyGRPCService) SignCSR(ctx context.Context, req *platformv1.CeremonySignCSRRequest) (*platformv1.CeremonySignCSRResponse, error) {
	in := &CeremonySignCSRRequest{
		Username: req.GetUsername(),
		SOPIN:    req.GetSoPin(),
		CSRPEM:   req.GetCsrPem(),
		Role:     ceremonyRoleToService[req.GetRole()],
	}
	out, err := s.service.SignCSR(ctx, in)
	if err != nil {
		return nil, ceremonyErrorToGRPC(err)
	}
	return &platformv1.CeremonySignCSRResponse{
		CertificatePem: out.CertificatePEM,
		ChainPem:       out.ChainPEM,
	}, nil
}
