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

// Device argument mapping for the MCP transport.
//
// The device_get and device_delete tools (pkg/api/mcp/tools.go) take the
// device as "device_id", a decimal string, while the pb requests carry a
// uint64 "id". The generic JSON round-trip would send {"id": N}, which the
// tools ignore, so these methods build their arguments explicitly.
//
// AttestDevice maps to the device_attest tool (pkg/api/mcp/tools_exec.go),
// which takes device_id as a string, the evidence base64-encoded and the
// server-issued challenge_id. The tool answers with the daemon's
// DeviceAttestationResult JSON, whose device_id is a decimal string and
// whose verdict field is "status", not "attestation_status", so the reply
// is decoded explicitly the way the gRPC servicer builds
// AttestDeviceResponse; a zero baseline time stays nil ("no baseline").

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func init() {
	mcpArgBuilders[platformv1.DeviceService_GetDevice_FullMethodName] = buildDeviceGetArgs
	mcpArgBuilders[platformv1.DeviceService_DeleteDevice_FullMethodName] = buildDeviceDeleteArgs

	grpcMethodToMCPToolMap[platformv1.DeviceService_AttestDevice_FullMethodName] = "device_attest"
	mcpArgBuilders[platformv1.DeviceService_AttestDevice_FullMethodName] = buildDeviceAttestArgs
	mcpReplyDecoders[platformv1.DeviceService_AttestDevice_FullMethodName] = decodeDeviceAttestResult
}

// buildDeviceAttestArgs builds the device_attest tool arguments. The
// challenge_id key is sent only when the caller names a challenge.
func buildDeviceAttestArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.AttestDeviceRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_AttestDevice_FullMethodName}
	}
	out := map[string]interface{}{
		"device_id": req.GetDeviceId(),
		"evidence":  base64.StdEncoding.EncodeToString(req.GetEvidence()),
	}
	if challengeID := req.GetChallengeId(); challengeID != "" {
		out["challenge_id"] = challengeID
	}
	return out, nil
}

// deviceAttestResult mirrors the daemon's DeviceAttestationResult JSON
// (pkg/api/daemon/device_quote_verifier.go). cryptographic_failure is not
// carried: AttestDeviceResponse has no field for it.
type deviceAttestResult struct {
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

// decodeDeviceAttestResult maps the device_attest verdict onto
// AttestDeviceResponse the way the gRPC servicer builds it.
func decodeDeviceAttestResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.AttestDeviceResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.DeviceService_AttestDevice_FullMethodName}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	var verdict deviceAttestResult
	if err := json.Unmarshal(data, &verdict); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Status = &platformv1.Status{Success: true, Message: "device attestation evaluated"}
	out.DeviceId = verdict.DeviceID
	out.Serial = verdict.Serial
	out.Model = verdict.Model
	out.Verified = verdict.Verified
	out.SignatureValid = verdict.SignatureValid
	out.NonceValid = verdict.NonceValid
	out.PcrsValid = verdict.PCRsValid
	out.AttestationStatus = verdict.Status
	out.Message = verdict.Message
	out.AttestedAt = timestamppb.New(verdict.AttestedAt)
	out.AkCertificateVerified = verdict.AKCertificateVerified
	out.PcrBaselineSource = verdict.PCRBaselineSource
	out.PcrBaselineRecordedAt = nil
	if !verdict.PCRBaselineRecordedAt.IsZero() {
		out.PcrBaselineRecordedAt = timestamppb.New(verdict.PCRBaselineRecordedAt)
	}
	out.PcrBaselineCaptured = verdict.PCRBaselineCaptured
	return nil
}

// buildDeviceGetArgs builds the device_get tool arguments.
func buildDeviceGetArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.GetDeviceRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_GetDevice_FullMethodName}
	}
	return deviceIDArgs(req.GetId()), nil
}

// buildDeviceDeleteArgs builds the device_delete tool arguments.
func buildDeviceDeleteArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.DeleteDeviceRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.DeviceService_DeleteDevice_FullMethodName}
	}
	return deviceIDArgs(req.GetId()), nil
}

// deviceIDArgs sends the device ID as a decimal string, the repo-wide
// uint64-on-the-wire convention.
func deviceIDArgs(id uint64) map[string]interface{} {
	return map[string]interface{}{"device_id": strconv.FormatUint(id, 10)}
}
