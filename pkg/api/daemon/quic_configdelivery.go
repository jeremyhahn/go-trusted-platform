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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Provisioning category (opcode 0xCF) handlers.
//
// The pre-enrollment config delivery verbs (get-nonce, fetch-config,
// sign-digest, poll/fulfill/list/get session) multiplex under
// quicwire.OpProvisioningCategory with the first payload byte selecting the
// sub-operation. Dispatch is map-based per project conventions. All
// handlers delegate to the ConfigDeliveryQUICService, which is backed by
// the same ConfigDeliveryGRPCService as the gRPC transport, so the typed
// configdelivery error -> status-code mapping (fetchConfigErrorMatchers,
// signDigestErrorMatchers, sessionErrorMatchers) is reused by
// construction; this file only translates the resulting gRPC codes to
// QUIC status bytes.
//
// Wire format: the QUIC payload codec keys on exact Go field names (it
// ignores codec/json struct tags), so every wire struct below mirrors
// its platformv1 protobuf counterpart byte-for-byte. The codec tags are
// documentation only, for future tag-aware codecs. FetchConfigResponse
// and PollSessionResponse use a protobuf ONEOF (interface-typed Result
// field) that does not round-trip through the codec, so those two
// responses are FLATTENED into single wire structs with a Result string
// discriminator ("delivered" | "pending"); the *ToProto / flatten
// helpers pin the mapping in both directions.

// ConfigDeliveryQUICService is the config delivery surface the QUIC
// transport delegates to. It is satisfied by *ConfigDeliveryGRPCService,
// guaranteeing identical semantics and error mapping across transports.
type ConfigDeliveryQUICService interface {
	GetNonce(ctx context.Context, req *platformv1.GetNonceRequest) (*platformv1.GetNonceResponse, error)
	FetchConfig(ctx context.Context, req *platformv1.FetchConfigRequest) (*platformv1.FetchConfigResponse, error)
	SignDigest(ctx context.Context, req *platformv1.SignDigestRequest) (*platformv1.SignDigestResponse, error)
	PollSession(ctx context.Context, req *platformv1.PollSessionRequest) (*platformv1.PollSessionResponse, error)
	FulfillSession(ctx context.Context, req *platformv1.FulfillSessionRequest) (*platformv1.FulfillSessionResponse, error)
	ListSessions(ctx context.Context, req *platformv1.ListSessionsRequest) (*platformv1.ListSessionsResponse, error)
	GetSession(ctx context.Context, req *platformv1.GetSessionRequest) (*platformv1.GetSessionResponse, error)
}

// Compile-time check: the gRPC service implements the QUIC surface.
var _ ConfigDeliveryQUICService = (*ConfigDeliveryGRPCService)(nil)

// =============================================================================
// Wire Types
// =============================================================================

// Result discriminator values for the flattened FetchConfig and
// PollSession responses, mirroring the protobuf oneof arms.
const (
	// ConfigDeliveryResultDelivered marks a response carrying a delivered
	// config (pb oneof arm DeliveredConfig).
	ConfigDeliveryResultDelivered = "delivered"
	// ConfigDeliveryResultPending marks a response carrying a pending
	// session (pb oneof arm PendingSession / pending_status).
	ConfigDeliveryResultPending = "pending"
)

// ConfigDeliveryGetNonceResponse mirrors platformv1.GetNonceResponse.
type ConfigDeliveryGetNonceResponse struct {
	Nonce string `codec:"nonce"`
}

// ConfigDeliveryFetchConfigRequest mirrors platformv1.FetchConfigRequest.
type ConfigDeliveryFetchConfigRequest struct {
	EkSerial   string `codec:"ek_serial"`
	MacAddress string `codec:"mac_address"`
	EkCert     string `codec:"ek_cert"`
	EabKeyId   string `codec:"eab_key_id"`
	EabHmac    string `codec:"eab_hmac"`
	Nonce      string `codec:"nonce"`
}

// ConfigDeliveryFetchConfigResponse is the FLAT wire form of
// platformv1.FetchConfigResponse. The pb oneof (delivered XOR pending)
// is flattened: Result selects the populated field group. When Result is
// "delivered", ConfigJson and Status carry the DeliveredConfig fields;
// when Result is "pending", SessionId, ProvisionUrl and
// PollIntervalSeconds carry the PendingSession fields.
type ConfigDeliveryFetchConfigResponse struct {
	Result              string `codec:"result"`
	ConfigJson          []byte `codec:"config_json"`
	Status              string `codec:"status"`
	SessionId           string `codec:"session_id"`
	ProvisionUrl        string `codec:"provision_url"`
	PollIntervalSeconds int32  `codec:"poll_interval_seconds"`
}

// ConfigDeliverySignDigestRequest mirrors platformv1.SignDigestRequest.
type ConfigDeliverySignDigestRequest struct {
	EkSerial   string `codec:"ek_serial"`
	MacAddress string `codec:"mac_address"`
	EkCert     string `codec:"ek_cert"`
	EabKeyId   string `codec:"eab_key_id"`
	EabHmac    string `codec:"eab_hmac"`
	Nonce      string `codec:"nonce"`
	Digest     []byte `codec:"digest"`
	KeyRef     string `codec:"key_ref"`
}

// ConfigDeliverySignDigestResponse mirrors platformv1.SignDigestResponse.
type ConfigDeliverySignDigestResponse struct {
	Signature []byte `codec:"signature"`
	CertPem   []byte `codec:"cert_pem"`
}

// ConfigDeliveryPollSessionRequest mirrors platformv1.PollSessionRequest.
type ConfigDeliveryPollSessionRequest struct {
	SessionId string `codec:"session_id"`
}

// ConfigDeliveryPollSessionResponse is the FLAT wire form of
// platformv1.PollSessionResponse. The pb oneof (delivered XOR
// pending_status) is flattened: Result selects the populated field
// group. When Result is "delivered", ConfigJson and Status carry the
// DeliveredConfig fields; when Result is "pending", PendingStatus
// carries the pb pending_status string.
type ConfigDeliveryPollSessionResponse struct {
	Result        string `codec:"result"`
	ConfigJson    []byte `codec:"config_json"`
	Status        string `codec:"status"`
	PendingStatus string `codec:"pending_status"`
}

// ConfigDeliveryFulfillSessionRequest mirrors
// platformv1.FulfillSessionRequest.
type ConfigDeliveryFulfillSessionRequest struct {
	SessionId string `codec:"session_id"`
	ProfileId uint64 `codec:"profile_id"`
}

// ConfigDeliveryFulfillSessionResponse mirrors
// platformv1.FulfillSessionResponse.
type ConfigDeliveryFulfillSessionResponse struct {
	Status string `codec:"status"`
}

// ConfigDeliveryListSessionsResponse mirrors
// platformv1.ListSessionsResponse. The session objects reuse the
// platformv1.ProvisioningSession message directly: it contains no oneof,
// so it (and its nested DeviceProfile / Timestamp messages) round-trips
// through the codec by Go field name on both ends.
type ConfigDeliveryListSessionsResponse struct {
	Sessions []*platformv1.ProvisioningSession `codec:"sessions"`
}

// ConfigDeliveryGetSessionRequest mirrors platformv1.GetSessionRequest.
type ConfigDeliveryGetSessionRequest struct {
	SessionId string `codec:"session_id"`
}

// ConfigDeliveryGetSessionResponse mirrors platformv1.GetSessionResponse.
type ConfigDeliveryGetSessionResponse struct {
	Session *platformv1.ProvisioningSession `codec:"session"`
}

// =============================================================================
// Oneof Flattening
// =============================================================================

// flattenFetchConfigResponse maps the pb oneof FetchConfigResponse onto
// the flat QUIC wire struct.
func flattenFetchConfigResponse(pb *platformv1.FetchConfigResponse) *ConfigDeliveryFetchConfigResponse {
	if pb == nil {
		return nil
	}
	if pending := pb.GetPending(); pending != nil {
		return &ConfigDeliveryFetchConfigResponse{
			Result:              ConfigDeliveryResultPending,
			SessionId:           pending.GetSessionId(),
			ProvisionUrl:        pending.GetProvisionUrl(),
			PollIntervalSeconds: pending.GetPollIntervalSeconds(),
		}
	}
	delivered := pb.GetDelivered()
	return &ConfigDeliveryFetchConfigResponse{
		Result:     ConfigDeliveryResultDelivered,
		ConfigJson: delivered.GetConfigJson(),
		Status:     delivered.GetStatus(),
	}
}

// ToProto maps the flat QUIC wire struct back onto the pb oneof
// FetchConfigResponse. It is the exact inverse of
// flattenFetchConfigResponse and is exported for the SDK QUIC transport
// adapter.
func (r *ConfigDeliveryFetchConfigResponse) ToProto() *platformv1.FetchConfigResponse {
	if r == nil {
		return nil
	}
	if r.Result == ConfigDeliveryResultPending {
		return &platformv1.FetchConfigResponse{
			Result: &platformv1.FetchConfigResponse_Pending{
				Pending: &platformv1.PendingSession{
					SessionId:           r.SessionId,
					ProvisionUrl:        r.ProvisionUrl,
					PollIntervalSeconds: r.PollIntervalSeconds,
				},
			},
		}
	}
	return &platformv1.FetchConfigResponse{
		Result: &platformv1.FetchConfigResponse_Delivered{
			Delivered: &platformv1.DeliveredConfig{
				ConfigJson: r.ConfigJson,
				Status:     r.Status,
			},
		},
	}
}

// flattenPollSessionResponse maps the pb oneof PollSessionResponse onto
// the flat QUIC wire struct.
func flattenPollSessionResponse(pb *platformv1.PollSessionResponse) *ConfigDeliveryPollSessionResponse {
	if pb == nil {
		return nil
	}
	if delivered := pb.GetDelivered(); delivered != nil {
		return &ConfigDeliveryPollSessionResponse{
			Result:     ConfigDeliveryResultDelivered,
			ConfigJson: delivered.GetConfigJson(),
			Status:     delivered.GetStatus(),
		}
	}
	return &ConfigDeliveryPollSessionResponse{
		Result:        ConfigDeliveryResultPending,
		PendingStatus: pb.GetPendingStatus(),
	}
}

// ToProto maps the flat QUIC wire struct back onto the pb oneof
// PollSessionResponse. It is the exact inverse of
// flattenPollSessionResponse and is exported for the SDK QUIC transport
// adapter.
func (r *ConfigDeliveryPollSessionResponse) ToProto() *platformv1.PollSessionResponse {
	if r == nil {
		return nil
	}
	if r.Result == ConfigDeliveryResultDelivered {
		return &platformv1.PollSessionResponse{
			Result: &platformv1.PollSessionResponse_Delivered{
				Delivered: &platformv1.DeliveredConfig{
					ConfigJson: r.ConfigJson,
					Status:     r.Status,
				},
			},
		}
	}
	return &platformv1.PollSessionResponse{
		Result: &platformv1.PollSessionResponse_PendingStatus{
			PendingStatus: r.PendingStatus,
		},
	}
}

// =============================================================================
// Error Mapping
// =============================================================================

// configDeliveryGRPCCodeToQUICStatus maps the gRPC status codes produced
// by the shared configdelivery matcher tables (fetchConfigErrorMatchers,
// signDigestErrorMatchers, sessionErrorMatchers) to QUIC status bytes.
// FailedPrecondition (REST 409, remote sign not configured) maps to
// StatusInvalidRequest since the QUIC status set has no precondition
// code; Unauthenticated maps to StatusUnauthorized.
var configDeliveryGRPCCodeToQUICStatus = map[codes.Code]byte{
	codes.InvalidArgument:    quicwire.StatusInvalidArgument,
	codes.Unauthenticated:    quicwire.StatusUnauthorized,
	codes.PermissionDenied:   quicwire.StatusPermissionDenied,
	codes.NotFound:           quicwire.StatusNotFound,
	codes.FailedPrecondition: quicwire.StatusInvalidRequest,
	codes.Unavailable:        quicwire.StatusUnavailable,
	codes.Internal:           quicwire.StatusInternalError,
}

// configDeliveryErrorToQUICResponse converts a gRPC status error from
// the shared ConfigDeliveryGRPCService into a QUIC error response,
// preserving the status-code semantics established by the gRPC matcher
// tables. Unknown codes map to StatusInternalError.
func (h *QUICServiceHandler) configDeliveryErrorToQUICResponse(op string, err error) *quicwire.Response {
	quicStatus := quicwire.StatusInternalError
	if mapped, ok := configDeliveryGRPCCodeToQUICStatus[status.Code(err)]; ok {
		quicStatus = mapped
	}
	return h.errorResponse(quicStatus, ErrQUICOperationFailed{Op: op, Cause: err})
}

// =============================================================================
// Dispatch
// =============================================================================

// configDeliveryQUICHandler handles a provisioning sub-operation.
type configDeliveryQUICHandler func(h *QUICServiceHandler, ctx context.Context, payload []byte) *quicwire.Response

// configDeliveryQUICDispatch routes provisioning sub-opcodes with O(1)
// lookup.
var configDeliveryQUICDispatch = map[byte]configDeliveryQUICHandler{
	quicwire.ProvisioningSubGetNonce:       (*QUICServiceHandler).handleProvisioningGetNonce,
	quicwire.ProvisioningSubFetchConfig:    (*QUICServiceHandler).handleProvisioningFetchConfig,
	quicwire.ProvisioningSubSignDigest:     (*QUICServiceHandler).handleProvisioningSignDigest,
	quicwire.ProvisioningSubPollSession:    (*QUICServiceHandler).handleProvisioningPollSession,
	quicwire.ProvisioningSubFulfillSession: (*QUICServiceHandler).handleProvisioningFulfillSession,
	quicwire.ProvisioningSubListSessions:   (*QUICServiceHandler).handleProvisioningListSessions,
	quicwire.ProvisioningSubGetSession:     (*QUICServiceHandler).handleProvisioningGetSession,
}

// handleProvisioningCategory routes a provisioning request to the
// correct sub-handler based on the first payload byte. A nil backing
// service yields the same typed unavailable error the gRPC
// requireService guard produces.
func (h *QUICServiceHandler) handleProvisioningCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.configDeliveryService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrConfigDeliveryServiceNotAvailable{})
	}
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	fn, ok := configDeliveryQUICDispatch[sub]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: sub})
	}
	return fn(h, ctx, payload)
}

// =============================================================================
// Sub-operation Handlers
// =============================================================================

func (h *QUICServiceHandler) handleProvisioningGetNonce(ctx context.Context, payload []byte) *quicwire.Response {
	pbResp, err := h.configDeliveryService.GetNonce(ctx, &platformv1.GetNonceRequest{})
	if err != nil {
		h.logger.Error(err, "failed to issue provisioning nonce")
		return h.configDeliveryErrorToQUICResponse("ProvisioningGetNonce", err)
	}
	return h.encodeConfigDeliveryResponse(&ConfigDeliveryGetNonceResponse{
		Nonce: pbResp.GetNonce(),
	})
}

func (h *QUICServiceHandler) handleProvisioningFetchConfig(ctx context.Context, payload []byte) *quicwire.Response {
	var fetchReq ConfigDeliveryFetchConfigRequest
	if err := quicwire.DecodePayload(payload, &fetchReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	pbResp, err := h.configDeliveryService.FetchConfig(ctx, &platformv1.FetchConfigRequest{
		EkSerial:   fetchReq.EkSerial,
		MacAddress: fetchReq.MacAddress,
		EkCert:     fetchReq.EkCert,
		EabKeyId:   fetchReq.EabKeyId,
		EabHmac:    fetchReq.EabHmac,
		Nonce:      fetchReq.Nonce,
	})
	if err != nil {
		h.logger.Error(err, "failed to fetch provisioning config", "ek_serial", fetchReq.EkSerial)
		return h.configDeliveryErrorToQUICResponse("ProvisioningFetchConfig", err)
	}
	return h.encodeConfigDeliveryResponse(flattenFetchConfigResponse(pbResp))
}

func (h *QUICServiceHandler) handleProvisioningSignDigest(ctx context.Context, payload []byte) *quicwire.Response {
	var signReq ConfigDeliverySignDigestRequest
	if err := quicwire.DecodePayload(payload, &signReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	pbResp, err := h.configDeliveryService.SignDigest(ctx, &platformv1.SignDigestRequest{
		EkSerial:   signReq.EkSerial,
		MacAddress: signReq.MacAddress,
		EkCert:     signReq.EkCert,
		EabKeyId:   signReq.EabKeyId,
		EabHmac:    signReq.EabHmac,
		Nonce:      signReq.Nonce,
		Digest:     signReq.Digest,
		KeyRef:     signReq.KeyRef,
	})
	if err != nil {
		h.logger.Error(err, "failed to sign provisioning digest", "ek_serial", signReq.EkSerial)
		return h.configDeliveryErrorToQUICResponse("ProvisioningSignDigest", err)
	}
	return h.encodeConfigDeliveryResponse(&ConfigDeliverySignDigestResponse{
		Signature: pbResp.GetSignature(),
		CertPem:   pbResp.GetCertPem(),
	})
}

func (h *QUICServiceHandler) handleProvisioningPollSession(ctx context.Context, payload []byte) *quicwire.Response {
	var pollReq ConfigDeliveryPollSessionRequest
	if err := quicwire.DecodePayload(payload, &pollReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if pollReq.SessionId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "session_id"})
	}

	pbResp, err := h.configDeliveryService.PollSession(ctx, &platformv1.PollSessionRequest{
		SessionId: pollReq.SessionId,
	})
	if err != nil {
		h.logger.Error(err, "failed to poll provisioning session", "session_id", pollReq.SessionId)
		return h.configDeliveryErrorToQUICResponse("ProvisioningPollSession", err)
	}
	return h.encodeConfigDeliveryResponse(flattenPollSessionResponse(pbResp))
}

func (h *QUICServiceHandler) handleProvisioningFulfillSession(ctx context.Context, payload []byte) *quicwire.Response {
	var fulfillReq ConfigDeliveryFulfillSessionRequest
	if err := quicwire.DecodePayload(payload, &fulfillReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if fulfillReq.SessionId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "session_id"})
	}

	pbResp, err := h.configDeliveryService.FulfillSession(ctx, &platformv1.FulfillSessionRequest{
		SessionId: fulfillReq.SessionId,
		ProfileId: fulfillReq.ProfileId,
	})
	if err != nil {
		h.logger.Error(err, "failed to fulfill provisioning session", "session_id", fulfillReq.SessionId)
		return h.configDeliveryErrorToQUICResponse("ProvisioningFulfillSession", err)
	}
	return h.encodeConfigDeliveryResponse(&ConfigDeliveryFulfillSessionResponse{
		Status: pbResp.GetStatus(),
	})
}

func (h *QUICServiceHandler) handleProvisioningListSessions(ctx context.Context, payload []byte) *quicwire.Response {
	pbResp, err := h.configDeliveryService.ListSessions(ctx, &platformv1.ListSessionsRequest{})
	if err != nil {
		h.logger.Error(err, "failed to list provisioning sessions")
		return h.configDeliveryErrorToQUICResponse("ProvisioningListSessions", err)
	}
	return h.encodeConfigDeliveryResponse(&ConfigDeliveryListSessionsResponse{
		Sessions: pbResp.GetSessions(),
	})
}

func (h *QUICServiceHandler) handleProvisioningGetSession(ctx context.Context, payload []byte) *quicwire.Response {
	var getReq ConfigDeliveryGetSessionRequest
	if err := quicwire.DecodePayload(payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if getReq.SessionId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "session_id"})
	}

	pbResp, err := h.configDeliveryService.GetSession(ctx, &platformv1.GetSessionRequest{
		SessionId: getReq.SessionId,
	})
	if err != nil {
		h.logger.Error(err, "failed to get provisioning session", "session_id", getReq.SessionId)
		return h.configDeliveryErrorToQUICResponse("ProvisioningGetSession", err)
	}
	return h.encodeConfigDeliveryResponse(&ConfigDeliveryGetSessionResponse{
		Session: pbResp.GetSession(),
	})
}

// encodeConfigDeliveryResponse encodes v as a StatusOK QUIC response.
func (h *QUICServiceHandler) encodeConfigDeliveryResponse(v interface{}) *quicwire.Response {
	payload, err := quicwire.EncodePayload(v)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}
	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}
