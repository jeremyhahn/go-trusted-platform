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

package ceremony

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/grpc"
)

// GRPCClient is a ceremony Service implementation backed by a gRPC
// CeremonyServiceClient. It is transport-agnostic in the same sense the rest
// of the SDK is: callers can supply any *grpc.ClientConn (real TCP, Unix
// socket, in-process testing bufconn) and the client works the same.
type GRPCClient struct {
	rpc platformv1.CeremonyServiceClient
}

// NewGRPCClient returns a ceremony Service backed by the supplied gRPC
// connection.
func NewGRPCClient(conn *grpc.ClientConn) *GRPCClient {
	return &GRPCClient{rpc: platformv1.NewCeremonyServiceClient(conn)}
}

// NewGRPCClientFromClient returns a ceremony Service backed by a raw proto
// client. Useful in tests where the caller already holds a client stub.
func NewGRPCClientFromClient(c platformv1.CeremonyServiceClient) *GRPCClient {
	return &GRPCClient{rpc: c}
}

// proto <-> SDK conversion maps. Map-based dispatch gives O(1) lookup and
// avoids switch ladders per project conventions.
var authenticatorTypeToProto = map[AuthenticatorType]platformv1.CeremonyAuthenticatorType{
	AuthenticatorUnspecified: platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_UNSPECIFIED,
	AuthenticatorPIV:         platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_PIV,
	AuthenticatorFIDO2:       platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_FIDO2,
	AuthenticatorSoftware:    platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_SOFTWARE,
}

var roleToProto = map[OfficerRole]platformv1.CeremonyOfficerRole{
	RoleUnspecified: platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_UNSPECIFIED,
	RoleSO:          platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_SO,
	RoleAdmin:       platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN,
	RoleUser:        platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_USER,
}

var stateFromProto = map[platformv1.CeremonyState]CeremonyState{
	platformv1.CeremonyState_CEREMONY_STATE_UNSPECIFIED:   StateUnknown,
	platformv1.CeremonyState_CEREMONY_STATE_UNINITIALIZED: StateUninitialized,
	platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS:   StateInProgress,
	platformv1.CeremonyState_CEREMONY_STATE_COMPLETE:      StateComplete,
}

// Init proxies Init to the gRPC server.
func (c *GRPCClient) Init(ctx context.Context, req *InitRequest) (*InitResponse, error) {
	if req == nil {
		req = &InitRequest{}
	}
	resp, err := c.rpc.Init(ctx, &platformv1.CeremonyInitRequest{
		SoPin:                  req.SOPIN,
		UserPin:                req.UserPIN,
		Threshold:              req.Threshold,
		Hostname:               req.Hostname,
		Sans:                   req.SANs,
		CredentialSealStrategy: req.CredentialSealStrategy,
	})
	if err != nil {
		return nil, &ErrInitFailed{Cause: err}
	}
	out := &InitResponse{
		CeremonyID:   resp.GetCeremonyId(),
		State:        stateFromProto[resp.GetState()],
		AdminCertPEM: resp.GetAdminCertPem(),
		AdminKeyPEM:  resp.GetAdminKeyPem(),
		SPKIPin:      resp.GetSpkiPin(),
	}
	if ts := resp.GetInitializedAt(); ts != nil {
		t := ts.AsTime()
		out.InitializedAt = &t
	}
	return out, nil
}

// Status proxies Status to the gRPC server.
func (c *GRPCClient) Status(ctx context.Context) (*StatusResponse, error) {
	resp, err := c.rpc.Status(ctx, &platformv1.CeremonyStatusRequest{})
	if err != nil {
		return nil, &ErrStatusFailed{Cause: err}
	}
	out := &StatusResponse{
		CeremonyID:       resp.GetCeremonyId(),
		State:            stateFromProto[resp.GetState()],
		Threshold:        resp.GetThreshold(),
		OfficersEnrolled: resp.GetOfficersEnrolled(),
		OfficersRequired: resp.GetOfficersRequired(),
	}
	if ts := resp.GetInitializedAt(); ts != nil {
		t := ts.AsTime()
		out.InitializedAt = &t
	}
	return out, nil
}

// ClaimCertBegin proxies ClaimCertBegin to the gRPC server.
func (c *GRPCClient) ClaimCertBegin(ctx context.Context, req *ClaimCertBeginRequest) (*ClaimCertBeginResponse, error) {
	if req == nil {
		req = &ClaimCertBeginRequest{}
	}
	resp, err := c.rpc.ClaimCertBegin(ctx, &platformv1.CeremonyClaimCertBeginRequest{
		Username:          req.Username,
		AuthenticatorType: authenticatorTypeToProto[req.AuthenticatorType],
		Slot:              req.Slot,
		CredentialId:      req.CredentialID,
	})
	if err != nil {
		return nil, &ErrClaimCertBeginFailed{Cause: err}
	}
	out := &ClaimCertBeginResponse{
		Nonce:       resp.GetNonce(),
		ChallengeID: resp.GetChallengeId(),
	}
	if ts := resp.GetExpiresAt(); ts != nil {
		t := ts.AsTime()
		out.ExpiresAt = &t
	}
	return out, nil
}

// ClaimCertComplete proxies ClaimCertComplete to the gRPC server.
func (c *GRPCClient) ClaimCertComplete(ctx context.Context, req *ClaimCertCompleteRequest) (*ClaimCertCompleteResponse, error) {
	if req == nil {
		req = &ClaimCertCompleteRequest{}
	}
	resp, err := c.rpc.ClaimCertComplete(ctx, &platformv1.CeremonyClaimCertCompleteRequest{
		Username:  req.Username,
		Nonce:     req.Nonce,
		Signature: req.Signature,
	})
	if err != nil {
		return nil, &ErrClaimCertCompleteFailed{Cause: err}
	}
	return &ClaimCertCompleteResponse{
		Certificate: resp.GetCertificatePem(),
		Chain:       resp.GetChainPem(),
	}, nil
}

// ClaimShare proxies ClaimShare to the gRPC server.
func (c *GRPCClient) ClaimShare(ctx context.Context, req *ClaimShareRequest) (*ClaimShareResponse, error) {
	if req == nil {
		req = &ClaimShareRequest{}
	}
	resp, err := c.rpc.ClaimShare(ctx, &platformv1.CeremonyClaimShareRequest{Username: req.Username})
	if err != nil {
		return nil, &ErrClaimShareFailed{Cause: err}
	}
	return &ClaimShareResponse{
		Share: resp.GetShare(),
		Index: resp.GetIndex(),
	}, nil
}

// SignCSR proxies SignCSR to the gRPC server.
func (c *GRPCClient) SignCSR(ctx context.Context, req *SignCSRRequest) (*SignCSRResponse, error) {
	if req == nil {
		req = &SignCSRRequest{}
	}
	resp, err := c.rpc.SignCSR(ctx, &platformv1.CeremonySignCSRRequest{
		Username: req.Username,
		SoPin:    req.SOPIN,
		CsrPem:   req.CSRPEM,
		Role:     roleToProto[req.Role],
	})
	if err != nil {
		return nil, &ErrSignCSRFailed{Cause: err}
	}
	return &SignCSRResponse{
		Certificate: resp.GetCertificatePem(),
		Chain:       resp.GetChainPem(),
	}, nil
}

// Compile-time interface check.
var _ Service = (*GRPCClient)(nil)
