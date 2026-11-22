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

import (
	"context"
	"errors"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestDeviceMCP_DeleteDevice_SendsDeviceIDString pins DeleteDevice to the
// registered device_delete tool with the device as a decimal "device_id".
func TestDeviceMCP_DeleteDevice_SendsDeviceIDString(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"device_delete": map[string]interface{}{"success": true},
	}, &calls)

	err := a.Connection().Invoke(context.Background(),
		platformv1.DeviceService_DeleteDevice_FullMethodName,
		&platformv1.DeleteDeviceRequest{Id: 18446744073709551615},
		&platformv1.DeleteDeviceResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "device_delete" {
		t.Fatalf("calls = %+v, want one device_delete call", calls)
	}
	if got := calls[0].Arguments["device_id"]; got != "18446744073709551615" {
		t.Errorf("device_id = %v, want the uint64 as a decimal string", got)
	}
	if _, has := calls[0].Arguments["id"]; has {
		t.Errorf("args = %v, carry the pb id key the tool ignores", calls[0].Arguments)
	}
}

// TestDeviceMCP_GetDevice_SendsDeviceIDString pins GetDevice's arguments to
// the device_get tool's "device_id".
func TestDeviceMCP_GetDevice_SendsDeviceIDString(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"device_get": map[string]interface{}{},
	}, &calls)

	err := a.Connection().Invoke(context.Background(),
		platformv1.DeviceService_GetDevice_FullMethodName,
		&platformv1.GetDeviceRequest{Id: 9},
		&platformv1.GetDeviceResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "device_get" || calls[0].Arguments["device_id"] != "9" {
		t.Fatalf("calls = %+v, want device_get with device_id 9", calls)
	}
}

// TestDeviceMCP_Lifecycle_CallsTheTransitionTools proves DisableDevice and
// EnableDevice reach the device_disable and device_enable tools with the
// argument names the server reads, and that the reply decodes.
func TestDeviceMCP_Lifecycle_CallsTheTransitionTools(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		// The server returns the pb response, so device_id is a JSON number.
		"device_disable": map[string]interface{}{"device_id": 42, "state": "suspended"},
		"device_enable":  map[string]interface{}{"device_id": 42, "state": "quarantined", "reattestation_requested": true},
	}, &calls)

	disabled := &platformv1.DeviceLifecycleResponse{}
	err := a.Connection().Invoke(context.Background(),
		platformv1.DeviceService_DisableDevice_FullMethodName,
		&platformv1.DisableDeviceRequest{DeviceId: "42", Reason: "rma pending"},
		disabled)
	if err != nil {
		t.Fatalf("Invoke disable: %v", err)
	}
	enabled := &platformv1.DeviceLifecycleResponse{}
	err = a.Connection().Invoke(context.Background(),
		platformv1.DeviceService_EnableDevice_FullMethodName,
		&platformv1.EnableDeviceRequest{DeviceId: "42"},
		enabled)
	if err != nil {
		t.Fatalf("Invoke enable: %v", err)
	}

	if len(calls) != 2 || calls[0].Name != "device_disable" || calls[1].Name != "device_enable" {
		t.Fatalf("calls = %+v, want device_disable then device_enable", calls)
	}
	if calls[0].Arguments["device_id"] != "42" || calls[0].Arguments["reason"] != "rma pending" {
		t.Errorf("disable args = %v, want device_id 42 and the reason", calls[0].Arguments)
	}
	if calls[1].Arguments["device_id"] != "42" {
		t.Errorf("enable args = %v, want device_id 42", calls[1].Arguments)
	}
	if disabled.GetState() != "suspended" || enabled.GetState() != "quarantined" || !enabled.GetReattestationRequested() {
		t.Errorf("replies = %+v / %+v, want suspended then quarantined with re-attestation", disabled, enabled)
	}
}

func TestDeviceMCP_ArgBuilders_RejectWrongRequestType(t *testing.T) {
	builders := map[string]mcpArgBuilder{
		platformv1.DeviceService_GetDevice_FullMethodName:    buildDeviceGetArgs,
		platformv1.DeviceService_DeleteDevice_FullMethodName: buildDeviceDeleteArgs,
		platformv1.DeviceService_AttestDevice_FullMethodName: buildDeviceAttestArgs,
	}
	for method, build := range builders {
		_, err := build(&platformv1.ListDevicesRequest{})
		var wrongType ErrUnexpectedArgsType
		if !errors.As(err, &wrongType) || wrongType.Method != method {
			t.Errorf("%s: err = %v, want ErrUnexpectedArgsType for the method", method, err)
		}
	}
}

func TestDeviceMCP_ReplyDecoders_RejectWrongReplyType(t *testing.T) {
	method := platformv1.DeviceService_AttestDevice_FullMethodName
	err := decodeDeviceAttestResult(map[string]interface{}{}, &platformv1.ListDevicesResponse{})
	var wrongType ErrUnexpectedReplyType
	if !errors.As(err, &wrongType) || wrongType.Method != method {
		t.Errorf("%s: err = %v, want ErrUnexpectedReplyType for the method", method, err)
	}
}

func TestDeviceMCP_AttestDevice_SendsChallengeAndDecodesVerdict(t *testing.T) {
	attestedAt := time.Date(2026, 11, 22, 10, 30, 0, 0, time.UTC)
	recordedAt := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"device_attest": map[string]interface{}{
			"device_id":                "42",
			"serial":                   "SN-42",
			"model":                    "edge-1",
			"verified":                 true,
			"ak_certificate_verified":  true,
			"signature_valid":          true,
			"nonce_valid":              true,
			"pcrs_valid":               true,
			"pcr_baseline_source":      "signed",
			"pcr_baseline_recorded_at": recordedAt.Format(time.RFC3339),
			"pcr_baseline_captured":    false,
			"cryptographic_failure":    false,
			"status":                   "verified",
			"message":                  "all checks passed",
			"attested_at":              attestedAt.Format(time.RFC3339),
		},
	}, &calls)

	reply := &platformv1.AttestDeviceResponse{}
	err := a.Connection().Invoke(context.Background(),
		platformv1.DeviceService_AttestDevice_FullMethodName,
		&platformv1.AttestDeviceRequest{DeviceId: "42", Evidence: []byte("quote"), ChallengeId: "ch-1"},
		reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "device_attest" {
		t.Fatalf("calls = %+v, want one device_attest call", calls)
	}
	args := calls[0].Arguments
	if args["device_id"] != "42" || args["evidence"] != "cXVvdGU=" || args["challenge_id"] != "ch-1" {
		t.Fatalf("arguments = %+v, want device_id 42, evidence cXVvdGU=, challenge_id ch-1", args)
	}

	if reply.GetDeviceId() != 42 || reply.GetSerial() != "SN-42" || reply.GetModel() != "edge-1" {
		t.Errorf("identity = %d %q %q, want 42 SN-42 edge-1", reply.GetDeviceId(), reply.GetSerial(), reply.GetModel())
	}
	if !reply.GetVerified() || !reply.GetAkCertificateVerified() || !reply.GetSignatureValid() ||
		!reply.GetNonceValid() || !reply.GetPcrsValid() || reply.GetPcrBaselineCaptured() {
		t.Errorf("verdict bools = %+v, want all checks true and no capture", reply)
	}
	if reply.GetAttestationStatus() != "verified" || reply.GetMessage() != "all checks passed" ||
		reply.GetPcrBaselineSource() != "signed" {
		t.Errorf("strings = %q %q %q, want verified, all checks passed, signed",
			reply.GetAttestationStatus(), reply.GetMessage(), reply.GetPcrBaselineSource())
	}
	if !reply.GetStatus().GetSuccess() || reply.GetStatus().GetMessage() != "device attestation evaluated" {
		t.Errorf("status = %+v, want success with device attestation evaluated", reply.GetStatus())
	}
	if reply.GetAttestedAt() == nil || !reply.GetAttestedAt().AsTime().Equal(attestedAt) {
		t.Errorf("attested_at = %v, want %v", reply.GetAttestedAt(), attestedAt)
	}
	if reply.GetPcrBaselineRecordedAt() == nil || !reply.GetPcrBaselineRecordedAt().AsTime().Equal(recordedAt) {
		t.Errorf("pcr_baseline_recorded_at = %v, want %v", reply.GetPcrBaselineRecordedAt(), recordedAt)
	}
}

func TestDeviceMCP_AttestDevice_NoChallengeAndZeroBaseline(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"device_attest": map[string]interface{}{
			"device_id":                "7",
			"verified":                 false,
			"pcr_baseline_recorded_at": "0001-01-01T00:00:00Z",
			"status":                   "failed",
			"attested_at":              "2026-11-22T10:30:00Z",
		},
	}, &calls)

	reply := &platformv1.AttestDeviceResponse{}
	err := a.Connection().Invoke(context.Background(),
		platformv1.DeviceService_AttestDevice_FullMethodName,
		&platformv1.AttestDeviceRequest{DeviceId: "7", Evidence: []byte("quote")},
		reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "device_attest" {
		t.Fatalf("calls = %+v, want one device_attest call", calls)
	}
	if _, sent := calls[0].Arguments["challenge_id"]; sent {
		t.Errorf("arguments = %+v, want no challenge_id key", calls[0].Arguments)
	}
	if reply.GetDeviceId() != 7 || reply.GetAttestationStatus() != "failed" {
		t.Errorf("reply = %+v, want device 7 failed", reply)
	}
	if reply.GetPcrBaselineRecordedAt() != nil {
		t.Errorf("pcr_baseline_recorded_at = %v, want nil for a zero time", reply.GetPcrBaselineRecordedAt())
	}
}
