// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The device_attest tool (pkg/api/mcp/tools.go) takes the device id and the
// base64 evidence and answers with the daemon's attestation result, whose
// "status" is the attestation verdict string rather than the pb Status, so
// the method carries its own argument builder and reply decoder.
func init() {
	method := platformv1.DeviceService_AttestDevice_FullMethodName
	grpcMethodToMCPToolMap[method] = "device_attest"
	mcpArgBuilders[method] = buildDeviceAttestArgs
	mcpReplyDecoders[method] = decodeDeviceAttestResult
}

// deviceAttestToolResult is the device_attest result: the JSON shape of the
// daemon's DeviceAttestationResult (pkg/api/daemon/device_quote_verifier.go).
type deviceAttestToolResult struct {
	DeviceID              uint64    `json:"device_id,string"`
	Serial                string    `json:"serial"`
	Model                 string    `json:"model"`
	Verified              bool      `json:"verified"`
	AKCertificateVerified bool      `json:"ak_certificate_verified"`
	SignatureValid        bool      `json:"signature_valid"`
	NonceValid            bool      `json:"nonce_valid"`
	PCRsValid             bool      `json:"pcrs_valid"`
	PCRBaselineSource     string    `json:"pcr_baseline_source"`
	PCRBaselineRecordedAt time.Time `json:"pcr_baseline_recorded_at"`
	PCRBaselineCaptured   bool      `json:"pcr_baseline_captured"`
	Status                string    `json:"status"`
	Message               string    `json:"message"`
	AttestedAt            time.Time `json:"attested_at"`
}

func buildDeviceAttestArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.AttestDeviceRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_AttestDevice_FullMethodName}
	}
	return map[string]interface{}{
		"device_id": req.GetDeviceId(),
		"evidence":  base64.StdEncoding.EncodeToString(req.GetEvidence()),
	}, nil
}

// decodeDeviceAttestResult fills the reply the way the gRPC handler does
// (pkg/api/daemon/device_grpc_service.go AttestDevice): a successful call
// status, the verdict as attestation_status and no timestamp for a zero time.
func decodeDeviceAttestResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.AttestDeviceResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_AttestDevice_FullMethodName}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	var decoded deviceAttestToolResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Status = &platformv1.Status{Success: true, Message: "device attestation evaluated"}
	out.DeviceId = decoded.DeviceID
	out.Serial = decoded.Serial
	out.Model = decoded.Model
	out.Verified = decoded.Verified
	out.SignatureValid = decoded.SignatureValid
	out.NonceValid = decoded.NonceValid
	out.PcrsValid = decoded.PCRsValid
	out.AttestationStatus = decoded.Status
	out.Message = decoded.Message
	out.AttestedAt = optionalTimestamp(decoded.AttestedAt)
	out.AkCertificateVerified = decoded.AKCertificateVerified
	out.PcrBaselineSource = decoded.PCRBaselineSource
	out.PcrBaselineRecordedAt = optionalTimestamp(decoded.PCRBaselineRecordedAt)
	out.PcrBaselineCaptured = decoded.PCRBaselineCaptured
	return nil
}

// optionalTimestamp encodes t, or nil when t is the zero time.
func optionalTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
