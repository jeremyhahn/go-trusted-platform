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

package mcp

// EAB (External Account Binding) argument and response mapping for the
// MCP transport.
//
// The platform_eab_* MCP tools (pkg/api/mcp/eab_tools.go) accept
// snake_case arguments and return domain JSON shapes produced by
// pkg/api/daemon/mcp_eab.go (eabCredentialJSON and friends):
//
//   - credentials render id / profile_id as DECIMAL STRINGS (the
//     repo-wide uint64-on-the-wire convention), status as the domain
//     name ("active" | "revoked" | "expired" | "used") and timestamps
//     as RFC3339 strings;
//   - action results ({"status": "revoked" | "deleted" | "used"}) carry
//     no pb Status message;
//   - the QR result base64-encodes the PNG under "qr_code".
//
// The generic pb JSON round-trip cannot express those shapes, so every
// EAB method has an explicit argument builder and reply decoder below.
// uint64 identifiers are always SENT as decimal strings too (the server
// helpers accept string or number).

import (
	"encoding/json"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func init() {
	// Tool routing — mirrors pkg/api/mcp/eab_tools.go registrations.
	for method, tool := range map[string]string{
		"/platform.v1.EABService/CreateCredential":          "platform_eab_create_credential",
		"/platform.v1.EABService/GetCredential":             "platform_eab_get_credential",
		"/platform.v1.EABService/GetCredentialByKeyID":      "platform_eab_get_credential_by_key_id",
		"/platform.v1.EABService/ListCredentials":           "platform_eab_list_credentials",
		"/platform.v1.EABService/RevokeCredential":          "platform_eab_revoke_credential",
		"/platform.v1.EABService/ValidateCredential":        "platform_eab_validate_credential",
		"/platform.v1.EABService/DeleteCredential":          "platform_eab_delete_credential",
		"/platform.v1.EABService/GetCredentialQRCode":       "platform_eab_get_credential_qr_code",
		"/platform.v1.EABService/GetEnrollmentURL":          "platform_eab_get_enrollment_url",
		"/platform.v1.EABService/MarkCredentialUsed":        "platform_eab_mark_credential_used",
		"/platform.v1.EABService/CleanupExpiredCredentials": "platform_eab_cleanup_expired_credentials",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	// Argument builders — uint64 IDs travel as decimal strings.
	for method, build := range map[string]mcpArgBuilder{
		"/platform.v1.EABService/CreateCredential":          buildEABCreateCredentialArgs,
		"/platform.v1.EABService/GetCredential":             buildEABGetCredentialArgs,
		"/platform.v1.EABService/GetCredentialByKeyID":      buildEABGetCredentialByKeyIDArgs,
		"/platform.v1.EABService/ListCredentials":           buildEABListCredentialsArgs,
		"/platform.v1.EABService/RevokeCredential":          buildEABRevokeCredentialArgs,
		"/platform.v1.EABService/ValidateCredential":        buildEABValidateCredentialArgs,
		"/platform.v1.EABService/DeleteCredential":          buildEABDeleteCredentialArgs,
		"/platform.v1.EABService/GetCredentialQRCode":       buildEABGetCredentialQRCodeArgs,
		"/platform.v1.EABService/GetEnrollmentURL":          buildEABGetEnrollmentURLArgs,
		"/platform.v1.EABService/MarkCredentialUsed":        buildEABMarkCredentialUsedArgs,
		"/platform.v1.EABService/CleanupExpiredCredentials": buildEABCleanupExpiredCredentialsArgs,
	} {
		mcpArgBuilders[method] = build
	}

	// Reply decoders — domain JSON shapes onto the pb replies.
	for method, decode := range map[string]mcpReplyDecoder{
		"/platform.v1.EABService/CreateCredential":          decodeEABCreateCredentialResult,
		"/platform.v1.EABService/GetCredential":             decodeEABGetCredentialResult,
		"/platform.v1.EABService/GetCredentialByKeyID":      decodeEABGetCredentialResult,
		"/platform.v1.EABService/ListCredentials":           decodeEABListCredentialsResult,
		"/platform.v1.EABService/RevokeCredential":          decodeEABRevokeCredentialResult,
		"/platform.v1.EABService/ValidateCredential":        decodeEABValidateCredentialResult,
		"/platform.v1.EABService/DeleteCredential":          decodeEABDeleteCredentialResult,
		"/platform.v1.EABService/GetCredentialQRCode":       decodeEABGetCredentialQRCodeResult,
		"/platform.v1.EABService/GetEnrollmentURL":          decodeEABGetEnrollmentURLResult,
		"/platform.v1.EABService/MarkCredentialUsed":        decodeEABMarkCredentialUsedResult,
		"/platform.v1.EABService/CleanupExpiredCredentials": decodeEABCleanupExpiredCredentialsResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

// =============================================================================
// Argument builders
// =============================================================================

func buildEABCreateCredentialArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.CreateEABCredentialRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/CreateCredential"}
	}
	out := map[string]interface{}{
		"profile_id": strconv.FormatUint(req.GetProfileId(), 10),
		"tenant_id":  req.GetTenantId(),
	}
	if req.GetExpiresInSeconds() != 0 {
		out["expires_in_seconds"] = req.GetExpiresInSeconds()
	}
	if req.GetHmacKeyLength() != 0 {
		out["hmac_key_length"] = req.GetHmacKeyLength()
	}
	return out, nil
}

func buildEABGetCredentialArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.GetEABCredentialRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/GetCredential"}
	}
	return map[string]interface{}{
		"credential_id": strconv.FormatUint(req.GetCredentialId(), 10),
	}, nil
}

func buildEABGetCredentialByKeyIDArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.GetEABCredentialByKeyIDRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/GetCredentialByKeyID"}
	}
	return map[string]interface{}{
		"key_id": req.GetKeyId(),
	}, nil
}

// eabStatusFilterName maps the pb status filter enum onto the short
// status names the platform_eab_list_credentials tool accepts.
var eabStatusFilterName = map[platformv1.EABCredentialStatus]string{
	platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE:  "active",
	platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED: "revoked",
	platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_EXPIRED: "expired",
	platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_USED:    "used",
}

func buildEABListCredentialsArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.ListEABCredentialsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/ListCredentials"}
	}
	out := map[string]interface{}{}
	if req.GetTenantId() != "" {
		out["tenant_id"] = req.GetTenantId()
	}
	if req.GetProfileId() != 0 {
		out["profile_id"] = strconv.FormatUint(req.GetProfileId(), 10)
	}
	if req.GetActiveOnly() {
		out["active_only"] = true
	}
	if name, hasFilter := eabStatusFilterName[req.GetStatusFilter()]; hasFilter {
		out["status"] = name
	}
	if pagination := req.GetPagination(); pagination != nil {
		if pagination.GetPage() != 0 {
			out["page"] = pagination.GetPage()
		}
		if pagination.GetPageSize() != 0 {
			out["page_size"] = pagination.GetPageSize()
		}
	}
	return out, nil
}

func buildEABRevokeCredentialArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.RevokeEABCredentialRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/RevokeCredential"}
	}
	out := map[string]interface{}{
		"credential_id": strconv.FormatUint(req.GetCredentialId(), 10),
	}
	if req.GetRevokerId() != 0 {
		out["revoker_id"] = strconv.FormatUint(req.GetRevokerId(), 10)
	}
	return out, nil
}

func buildEABValidateCredentialArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.ValidateEABCredentialRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/ValidateCredential"}
	}
	return map[string]interface{}{
		"key_id":   req.GetKeyId(),
		"hmac_key": req.GetHmacKey(),
	}, nil
}

func buildEABDeleteCredentialArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.DeleteEABCredentialRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/DeleteCredential"}
	}
	return map[string]interface{}{
		"credential_id": strconv.FormatUint(req.GetCredentialId(), 10),
	}, nil
}

func buildEABGetCredentialQRCodeArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.GetEABCredentialQRCodeRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/GetCredentialQRCode"}
	}
	out := map[string]interface{}{
		"credential_id": strconv.FormatUint(req.GetCredentialId(), 10),
	}
	if req.GetSize() != 0 {
		out["size"] = req.GetSize()
	}
	return out, nil
}

func buildEABGetEnrollmentURLArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.GetEABEnrollmentURLRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/GetEnrollmentURL"}
	}
	out := map[string]interface{}{
		"credential_id": strconv.FormatUint(req.GetCredentialId(), 10),
	}
	if req.GetPath() != "" {
		out["path"] = req.GetPath()
	}
	return out, nil
}

func buildEABMarkCredentialUsedArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.MarkEABCredentialUsedRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/MarkCredentialUsed"}
	}
	return map[string]interface{}{
		"credential_id": strconv.FormatUint(req.GetCredentialId(), 10),
	}, nil
}

func buildEABCleanupExpiredCredentialsArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.CleanupExpiredEABCredentialsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.EABService/CleanupExpiredCredentials"}
	}
	out := map[string]interface{}{}
	if req.GetTenantId() != "" {
		out["tenant_id"] = req.GetTenantId()
	}
	return out, nil
}

// =============================================================================
// Reply wire shapes
// =============================================================================

// eabFlexUint64 decodes a uint64 that may arrive as a decimal string
// (the canonical wire form) or a JSON number (legacy / hand-written
// clients).
type eabFlexUint64 uint64

// UnmarshalJSON implements json.Unmarshaler.
func (u *eabFlexUint64) UnmarshalJSON(data []byte) error {
	if len(data) > 1 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		*u = eabFlexUint64(n)
		return nil
	}
	var n uint64
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*u = eabFlexUint64(n)
	return nil
}

// eabCredentialWire mirrors the JSON produced by the daemon's
// eabCredentialJSON helper (pkg/api/daemon/mcp_eab.go).
type eabCredentialWire struct {
	ID        eabFlexUint64 `json:"id"`
	KeyID     string        `json:"key_id"`
	HMACKey   string        `json:"hmac_key,omitempty"`
	ProfileID eabFlexUint64 `json:"profile_id"`
	TenantID  string        `json:"tenant_id"`
	Status    string        `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at,omitempty"`
	UsedAt    time.Time     `json:"used_at,omitempty"`
}

// eabWireStatusToPb maps the domain status names onto the platform.v1
// enum with O(1) lookup.
var eabWireStatusToPb = map[string]platformv1.EABCredentialStatus{
	"active":  platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE,
	"revoked": platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED,
	"expired": platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_EXPIRED,
	"used":    platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_USED,
}

// toPb converts the wire credential to its protobuf representation.
func (w *eabCredentialWire) toPb() *platformv1.EABCredential {
	pb := &platformv1.EABCredential{
		Id:        uint64(w.ID),
		KeyId:     w.KeyID,
		HmacKey:   w.HMACKey,
		ProfileId: uint64(w.ProfileID),
		TenantId:  w.TenantID,
		Status:    eabWireStatusToPb[w.Status],
	}
	if !w.CreatedAt.IsZero() {
		pb.CreatedAt = timestamppb.New(w.CreatedAt)
	}
	if !w.ExpiresAt.IsZero() {
		pb.ExpiresAt = timestamppb.New(w.ExpiresAt)
	}
	if !w.UsedAt.IsZero() {
		pb.UsedAt = timestamppb.New(w.UsedAt)
	}
	return pb
}

// decodeEABResult re-marshals a generic MCP tool result and decodes it
// into the supplied wire struct.
func decodeEABResult(result interface{}, wire interface{}) error {
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, wire); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	return nil
}

// =============================================================================
// Reply decoders
// =============================================================================

func decodeEABCreateCredentialResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateEABCredentialResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.EABService/CreateCredential"}
	}
	var wire eabCredentialWire
	if err := decodeEABResult(result, &wire); err != nil {
		return err
	}
	out.Credential = wire.toPb()
	out.Timestamp = timestamppb.Now()
	return nil
}

func decodeEABGetCredentialResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetEABCredentialResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.EABService/GetCredential"}
	}
	var wire eabCredentialWire
	if err := decodeEABResult(result, &wire); err != nil {
		return err
	}
	out.Credential = wire.toPb()
	out.Timestamp = timestamppb.Now()
	return nil
}

// eabListWire mirrors the JSON produced by the daemon's
// EABListCredentials MCP handler.
type eabListWire struct {
	Credentials []eabCredentialWire `json:"credentials"`
	Total       int64               `json:"total"`
	Page        uint32              `json:"page"`
	PageSize    uint32              `json:"page_size"`
}

func decodeEABListCredentialsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListEABCredentialsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.EABService/ListCredentials"}
	}
	var wire eabListWire
	if err := decodeEABResult(result, &wire); err != nil {
		return err
	}
	out.Credentials = make([]*platformv1.EABCredential, 0, len(wire.Credentials))
	for i := range wire.Credentials {
		out.Credentials = append(out.Credentials, wire.Credentials[i].toPb())
	}
	out.Total = wire.Total
	if wire.PageSize > 0 {
		page := wire.Page
		if page == 0 {
			page = 1
		}
		out.Pagination = &platformv1.PaginationResponse{
			Page:       page,
			PageSize:   wire.PageSize,
			TotalPages: uint32((uint64(wire.Total) + uint64(wire.PageSize) - 1) / uint64(wire.PageSize)),
			TotalItems: uint64(wire.Total),
		}
	}
	out.Timestamp = timestamppb.Now()
	return nil
}

// eabActionWire mirrors the JSON action results ({"status": "revoked" |
// "deleted" | "used", ...}) produced by the daemon MCP handlers.
type eabActionWire struct {
	Status string `json:"status"`
}

// eabActionStatus builds the pb Status message for an action result.
func eabActionStatus(wire eabActionWire) *platformv1.Status {
	return &platformv1.Status{
		Success: wire.Status != "",
		Message: "credential " + wire.Status,
	}
}

func decodeEABRevokeCredentialResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.RevokeEABCredentialResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.EABService/RevokeCredential"}
	}
	var wire eabActionWire
	if err := decodeEABResult(result, &wire); err != nil {
		return err
	}
	out.Status = eabActionStatus(wire)
	out.Timestamp = timestamppb.Now()
	return nil
}

// eabValidateWire mirrors the JSON produced by the daemon's
// EABValidateCredential MCP handler.
type eabValidateWire struct {
	Valid        bool               `json:"valid"`
	Credential   *eabCredentialWire `json:"credential,omitempty"`
	ErrorMessage string             `json:"error_message,omitempty"`
}

func decodeEABValidateCredentialResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ValidateEABCredentialResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.EABService/ValidateCredential"}
	}
	var wire eabValidateWire
	if err := decodeEABResult(result, &wire); err != nil {
		return err
	}
	out.Valid = wire.Valid
	out.ErrorMessage = wire.ErrorMessage
	if wire.Credential != nil {
		out.Credential = wire.Credential.toPb()
	}
	out.Timestamp = timestamppb.Now()
	return nil
}

func decodeEABDeleteCredentialResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeleteEABCredentialResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.EABService/DeleteCredential"}
	}
	var wire eabActionWire
	if err := decodeEABResult(result, &wire); err != nil {
		return err
	}
	out.Status = eabActionStatus(wire)
	out.Timestamp = timestamppb.Now()
	return nil
}

// eabQRCodeWire mirrors the JSON produced by the daemon's
// EABGetCredentialQRCode MCP handler; qr_code carries the PNG as
// standard base64.
type eabQRCodeWire struct {
	ContentType string `json:"content_type"`
	QRCode      []byte `json:"qr_code"`
}

func decodeEABGetCredentialQRCodeResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetEABCredentialQRCodeResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.EABService/GetCredentialQRCode"}
	}
	var wire eabQRCodeWire
	if err := decodeEABResult(result, &wire); err != nil {
		return err
	}
	out.QrCode = wire.QRCode
	out.ContentType = wire.ContentType
	out.Timestamp = timestamppb.Now()
	return nil
}

// eabURLWire mirrors the JSON produced by the daemon's
// EABGetEnrollmentURL MCP handler.
type eabURLWire struct {
	URL string `json:"url"`
}

func decodeEABGetEnrollmentURLResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetEABEnrollmentURLResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.EABService/GetEnrollmentURL"}
	}
	var wire eabURLWire
	if err := decodeEABResult(result, &wire); err != nil {
		return err
	}
	out.Url = wire.URL
	out.Timestamp = timestamppb.Now()
	return nil
}

func decodeEABMarkCredentialUsedResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.MarkEABCredentialUsedResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.EABService/MarkCredentialUsed"}
	}
	var wire eabActionWire
	if err := decodeEABResult(result, &wire); err != nil {
		return err
	}
	out.Status = eabActionStatus(wire)
	out.Timestamp = timestamppb.Now()
	return nil
}

// eabCleanupWire mirrors the JSON produced by the daemon's
// EABCleanupExpiredCredentials MCP handler.
type eabCleanupWire struct {
	DeletedCount int32  `json:"deleted_count"`
	Status       string `json:"status"`
}

func decodeEABCleanupExpiredCredentialsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.CleanupExpiredEABCredentialsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.EABService/CleanupExpiredCredentials"}
	}
	var wire eabCleanupWire
	if err := decodeEABResult(result, &wire); err != nil {
		return err
	}
	out.DeletedCount = wire.DeletedCount
	out.Status = &platformv1.Status{Success: wire.Status == "ok", Message: wire.Status}
	out.Timestamp = timestamppb.Now()
	return nil
}
