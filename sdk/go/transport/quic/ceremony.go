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

package quic

// Ceremony wire support for the QUIC transport.
//
// The ceremony sub-operations multiplex under OpCeremonyCategory (0x9A). The
// daemon dispatcher (pkg/api/daemon/phase35_quic.go::ceremonyQUICDispatch)
// answers with quicwire.Ceremony*Resp structs that carry the state as a
// string and times as time.Time. Init returns only the ceremony id, state
// and time; the admin credential fields of the pb reply travel the separate
// /init path, so they stay empty here.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

var ceremonyRequestEncoders = map[string]categoryRequestEncoder{
	platformv1.CeremonyService_Init_FullMethodName: requestEncoder(platformv1.CeremonyService_Init_FullMethodName,
		func(r *platformv1.CeremonyInitRequest) (interface{}, error) {
			return &quicwire.CeremonyInitReq{
				SOPIN:                  r.GetSoPin(),
				UserPIN:                r.GetUserPin(),
				Threshold:              r.GetThreshold(),
				Hostname:               r.GetHostname(),
				SANs:                   r.GetSans(),
				CredentialSealStrategy: r.GetCredentialSealStrategy(),
			}, nil
		}),
	platformv1.CeremonyService_ClaimCertBegin_FullMethodName: requestEncoder(platformv1.CeremonyService_ClaimCertBegin_FullMethodName,
		func(r *platformv1.CeremonyClaimCertBeginRequest) (interface{}, error) {
			authenticator, err := ceremonysdk.AuthenticatorTypeToWire(r.GetAuthenticatorType())
			if err != nil {
				return nil, err
			}
			return &quicwire.CeremonyClaimCertBeginReq{
				Username:          r.GetUsername(),
				AuthenticatorType: authenticator,
				Slot:              r.GetSlot(),
				CredentialID:      r.GetCredentialId(),
			}, nil
		}),
	platformv1.CeremonyService_ClaimCertComplete_FullMethodName: requestEncoder(platformv1.CeremonyService_ClaimCertComplete_FullMethodName,
		func(r *platformv1.CeremonyClaimCertCompleteRequest) (interface{}, error) {
			return &quicwire.CeremonyClaimCertCompleteReq{
				Username:  r.GetUsername(),
				Nonce:     r.GetNonce(),
				Signature: r.GetSignature(),
			}, nil
		}),
	platformv1.CeremonyService_ClaimShareBegin_FullMethodName: requestEncoder(platformv1.CeremonyService_ClaimShareBegin_FullMethodName,
		func(r *platformv1.CeremonyClaimShareBeginRequest) (interface{}, error) {
			return &quicwire.CeremonyClaimShareBeginReq{Username: r.GetUsername()}, nil
		}),
	platformv1.CeremonyService_ClaimShareComplete_FullMethodName: requestEncoder(platformv1.CeremonyService_ClaimShareComplete_FullMethodName,
		func(r *platformv1.CeremonyClaimShareCompleteRequest) (interface{}, error) {
			return &quicwire.CeremonyClaimShareCompleteReq{
				Username:  r.GetUsername(),
				Nonce:     r.GetNonce(),
				Signature: r.GetSignature(),
			}, nil
		}),
	platformv1.CeremonyService_SignCSR_FullMethodName: requestEncoder(platformv1.CeremonyService_SignCSR_FullMethodName,
		func(r *platformv1.CeremonySignCSRRequest) (interface{}, error) {
			role, err := ceremonysdk.OfficerRoleToWire(r.GetRole())
			if err != nil {
				return nil, err
			}
			return &quicwire.CeremonySignCSRReq{
				Username: r.GetUsername(),
				SOPIN:    r.GetSoPin(),
				CSRPEM:   r.GetCsrPem(),
				Role:     role,
			}, nil
		}),
}

var ceremonyResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.CeremonyService_Init_FullMethodName: responseDecoder(platformv1.CeremonyService_Init_FullMethodName,
		func(w *quicwire.CeremonyInitResp, out *platformv1.CeremonyInitResponse) error {
			state, err := ceremonysdk.StateFromWire(w.State)
			if err != nil {
				return err
			}
			out.CeremonyId = w.CeremonyID
			out.State = state
			out.InitializedAt = ceremonysdk.TimestampOrNil(w.InitializedAt)
			out.AdminCertPem = w.AdminCertPEM
			out.AdminKeyPem = w.AdminKeyPEM
			out.SpkiPin = w.SPKIPin
			return nil
		}),
	platformv1.CeremonyService_Status_FullMethodName: responseDecoder(platformv1.CeremonyService_Status_FullMethodName,
		func(w *quicwire.CeremonyStatusResp, out *platformv1.CeremonyStatusResponse) error {
			state, err := ceremonysdk.StateFromWire(w.State)
			if err != nil {
				return err
			}
			out.CeremonyId = w.CeremonyID
			out.State = state
			out.Threshold = w.Threshold
			out.OfficersEnrolled = w.OfficersEnrolled
			out.OfficersRequired = w.OfficersRequired
			out.InitializedAt = ceremonysdk.TimestampOrNil(w.InitializedAt)
			return nil
		}),
	platformv1.CeremonyService_ClaimCertBegin_FullMethodName: responseDecoder(platformv1.CeremonyService_ClaimCertBegin_FullMethodName,
		func(w *quicwire.CeremonyClaimCertBeginResp, out *platformv1.CeremonyClaimCertBeginResponse) error {
			out.Nonce = w.Nonce
			out.ChallengeId = w.ChallengeID
			out.ExpiresAt = ceremonysdk.TimestampOrNil(w.ExpiresAt)
			return nil
		}),
	platformv1.CeremonyService_ClaimCertComplete_FullMethodName: responseDecoder(platformv1.CeremonyService_ClaimCertComplete_FullMethodName,
		func(w *quicwire.CeremonyClaimCertCompleteResp, out *platformv1.CeremonyClaimCertCompleteResponse) error {
			out.CertificatePem = w.CertificatePEM
			out.ChainPem = w.ChainPEM
			return nil
		}),
	platformv1.CeremonyService_ClaimShareBegin_FullMethodName: responseDecoder(platformv1.CeremonyService_ClaimShareBegin_FullMethodName,
		func(w *quicwire.CeremonyClaimShareBeginResp, out *platformv1.CeremonyClaimShareBeginResponse) error {
			out.Nonce = w.Nonce
			out.ExpiresAt = ceremonysdk.TimestampOrNil(w.ExpiresAt)
			return nil
		}),
	platformv1.CeremonyService_ClaimShareComplete_FullMethodName: responseDecoder(platformv1.CeremonyService_ClaimShareComplete_FullMethodName,
		func(w *quicwire.CeremonyClaimShareCompleteResp, out *platformv1.CeremonyClaimShareCompleteResponse) error {
			out.Share = w.Share
			out.Index = w.Index
			return nil
		}),
	platformv1.CeremonyService_SignCSR_FullMethodName: responseDecoder(platformv1.CeremonyService_SignCSR_FullMethodName,
		func(w *quicwire.CeremonySignCSRResp, out *platformv1.CeremonySignCSRResponse) error {
			out.CertificatePem = w.CertificatePEM
			out.ChainPem = w.ChainPEM
			return nil
		}),
}

func init() {
	registerCategoryCodecs(ceremonyRequestEncoders, ceremonyResponseDecoders)
}
