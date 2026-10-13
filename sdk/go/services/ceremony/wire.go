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

// Wire mapping shared by the QUIC, MCP and REST transports.
//
// Those transports carry the ceremony enums as the lowercase strings the
// daemon uses ("piv", "so", "in_progress") and times as RFC 3339, while the
// gRPC messages carry enums and google.protobuf.Timestamp. The generic JSON
// round-trip cannot bridge the two, so the converters below are the single
// canonical mapping the transports delegate to.

import (
	"encoding/json"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var authenticatorTypeFromProto = map[platformv1.CeremonyAuthenticatorType]AuthenticatorType{
	platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_UNSPECIFIED: AuthenticatorUnspecified,
	platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_PIV:         AuthenticatorPIV,
	platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_FIDO2:       AuthenticatorFIDO2,
	platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_SOFTWARE:    AuthenticatorSoftware,
}

var roleFromProto = map[platformv1.CeremonyOfficerRole]OfficerRole{
	platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_UNSPECIFIED: RoleUnspecified,
	platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_SO:          RoleSO,
	platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN:       RoleAdmin,
	platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_USER:        RoleUser,
}

var stateToProto = map[CeremonyState]platformv1.CeremonyState{
	StateUnknown:       platformv1.CeremonyState_CEREMONY_STATE_UNSPECIFIED,
	StateUninitialized: platformv1.CeremonyState_CEREMONY_STATE_UNINITIALIZED,
	StateInProgress:    platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS,
	StateComplete:      platformv1.CeremonyState_CEREMONY_STATE_COMPLETE,
}

// AuthenticatorTypeToWire returns the daemon's string form of an
// authenticator type, or ErrUnknownWireValue for a value outside the enum.
func AuthenticatorTypeToWire(t platformv1.CeremonyAuthenticatorType) (string, error) {
	v, ok := authenticatorTypeFromProto[t]
	if !ok {
		return "", &ErrUnknownWireValue{Kind: "authenticator_type", Value: t.String()}
	}
	return string(v), nil
}

// OfficerRoleToWire returns the daemon's string form of an officer role, or
// ErrUnknownWireValue for a value outside the enum.
func OfficerRoleToWire(r platformv1.CeremonyOfficerRole) (string, error) {
	v, ok := roleFromProto[r]
	if !ok {
		return "", &ErrUnknownWireValue{Kind: "role", Value: r.String()}
	}
	return string(v), nil
}

// StateFromWire maps the daemon's state string onto the pb enum. The empty
// string is UNSPECIFIED; any other unrecognised string is an
// ErrUnknownWireValue rather than a silent UNSPECIFIED.
func StateFromWire(s string) (platformv1.CeremonyState, error) {
	if s == "" {
		return platformv1.CeremonyState_CEREMONY_STATE_UNSPECIFIED, nil
	}
	v, ok := stateToProto[CeremonyState(s)]
	if !ok {
		return platformv1.CeremonyState_CEREMONY_STATE_UNSPECIFIED, &ErrUnknownWireValue{Kind: "state", Value: s}
	}
	return v, nil
}

// TimestampOrNil converts a wire time to a pb timestamp, mapping the zero
// time (the daemon's "not set") to nil.
func TimestampOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

type initJSON struct {
	CeremonyID    string    `json:"ceremony_id"`
	State         string    `json:"state"`
	InitializedAt time.Time `json:"initialized_at"`
	AdminCertPEM  string    `json:"admin_cert_pem"`
	AdminKeyPEM   string    `json:"admin_key_pem"`
	SPKIPin       string    `json:"spki_pin"`
}

type statusJSON struct {
	CeremonyID       string    `json:"ceremony_id"`
	State            string    `json:"state"`
	Threshold        string    `json:"threshold"`
	OfficersEnrolled int32     `json:"officers_enrolled"`
	OfficersRequired int32     `json:"officers_required"`
	InitializedAt    time.Time `json:"initialized_at"`
}

type challengeJSON struct {
	Nonce       string    `json:"nonce"`
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// DecodeInitJSON decodes the REST / MCP Init result, including the
// one-shot admin bundle and the daemon's SPKI pin.
func DecodeInitJSON(data []byte) (*platformv1.CeremonyInitResponse, error) {
	var w initJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "init", Err: err}
	}
	state, err := StateFromWire(w.State)
	if err != nil {
		return nil, err
	}
	return &platformv1.CeremonyInitResponse{
		CeremonyId:    w.CeremonyID,
		State:         state,
		InitializedAt: TimestampOrNil(w.InitializedAt),
		AdminCertPem:  w.AdminCertPEM,
		AdminKeyPem:   w.AdminKeyPEM,
		SpkiPin:       w.SPKIPin,
	}, nil
}

// DecodeStatusJSON decodes the REST / MCP Status result.
func DecodeStatusJSON(data []byte) (*platformv1.CeremonyStatusResponse, error) {
	var w statusJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "status", Err: err}
	}
	state, err := StateFromWire(w.State)
	if err != nil {
		return nil, err
	}
	return &platformv1.CeremonyStatusResponse{
		CeremonyId:       w.CeremonyID,
		State:            state,
		Threshold:        w.Threshold,
		OfficersEnrolled: w.OfficersEnrolled,
		OfficersRequired: w.OfficersRequired,
		InitializedAt:    TimestampOrNil(w.InitializedAt),
	}, nil
}

// DecodeClaimCertBeginJSON decodes the REST / MCP ClaimCertBegin result.
func DecodeClaimCertBeginJSON(data []byte) (*platformv1.CeremonyClaimCertBeginResponse, error) {
	var w challengeJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "claim-cert begin", Err: err}
	}
	return &platformv1.CeremonyClaimCertBeginResponse{
		Nonce:       w.Nonce,
		ChallengeId: w.ChallengeID,
		ExpiresAt:   TimestampOrNil(w.ExpiresAt),
	}, nil
}

// DecodeClaimShareBeginJSON decodes the REST / MCP ClaimShareBegin result.
func DecodeClaimShareBeginJSON(data []byte) (*platformv1.CeremonyClaimShareBeginResponse, error) {
	var w challengeJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, &ErrWireDecode{Message: "claim-share begin", Err: err}
	}
	return &platformv1.CeremonyClaimShareBeginResponse{
		Nonce:     w.Nonce,
		ExpiresAt: TimestampOrNil(w.ExpiresAt),
	}, nil
}
