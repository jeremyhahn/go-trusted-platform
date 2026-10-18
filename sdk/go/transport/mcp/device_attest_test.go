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
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestDeviceAttestMCP_SendsEvidenceAndDecodesVerdict(t *testing.T) {
	attestedAt := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{"device_attest": map[string]interface{}{
		"device_id":                "42",
		"serial":                   "SN-42",
		"model":                    "edge-1",
		"verified":                 true,
		"ak_certificate_verified":  true,
		"signature_valid":          true,
		"nonce_valid":              true,
		"pcrs_valid":               true,
		"pcr_baseline_source":      "tofu",
		"pcr_baseline_recorded_at": "0001-01-01T00:00:00Z",
		"pcr_baseline_captured":    true,
		"cryptographic_failure":    false,
		"status":                   "verified",
		"message":                  "all checks passed",
		"attested_at":              attestedAt.Format(time.RFC3339),
	}}, &calls)

	evidence := []byte{0x00, 0x01, 0xfe, 0xff}
	resp := &platformv1.AttestDeviceResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_AttestDevice_FullMethodName,
		&platformv1.AttestDeviceRequest{DeviceId: "42", Evidence: evidence}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "device_attest" {
		t.Fatalf("calls = %+v, want one device_attest call", calls)
	}
	if got := calls[0].Arguments["device_id"]; got != "42" {
		t.Errorf("device_id = %v, want 42", got)
	}
	if got := calls[0].Arguments["evidence"]; got != base64.StdEncoding.EncodeToString(evidence) {
		t.Errorf("evidence = %v, want standard base64 of the evidence", got)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Errorf("status = %v, want success", resp.GetStatus())
	}
	if resp.GetDeviceId() != 42 || resp.GetSerial() != "SN-42" || resp.GetModel() != "edge-1" {
		t.Errorf("identity = %d/%s/%s", resp.GetDeviceId(), resp.GetSerial(), resp.GetModel())
	}
	if !resp.GetVerified() || !resp.GetAkCertificateVerified() || !resp.GetSignatureValid() ||
		!resp.GetNonceValid() || !resp.GetPcrsValid() || !resp.GetPcrBaselineCaptured() {
		t.Errorf("checks = %+v, want every check true", resp)
	}
	if resp.GetAttestationStatus() != "verified" || resp.GetMessage() != "all checks passed" {
		t.Errorf("verdict = %q/%q", resp.GetAttestationStatus(), resp.GetMessage())
	}
	if resp.GetPcrBaselineSource() != "tofu" {
		t.Errorf("pcr_baseline_source = %q, want tofu", resp.GetPcrBaselineSource())
	}
	if !resp.GetAttestedAt().AsTime().Equal(attestedAt) {
		t.Errorf("attested_at = %v, want %v", resp.GetAttestedAt().AsTime(), attestedAt)
	}
	if resp.GetPcrBaselineRecordedAt() != nil {
		t.Errorf("pcr_baseline_recorded_at = %v, want nil for the zero time", resp.GetPcrBaselineRecordedAt())
	}
}

func TestDeviceAttestMCP_MalformedResultFails(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{"device_attest": map[string]interface{}{
		"device_id": "not-a-number",
	}}, &calls)

	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_AttestDevice_FullMethodName,
		&platformv1.AttestDeviceRequest{DeviceId: "42"}, &platformv1.AttestDeviceResponse{})
	if err == nil {
		t.Fatal("Invoke succeeded on a non-numeric device_id, want a decode error")
	}
}

func TestDeviceAttestMCP_RejectsWrongMessageTypes(t *testing.T) {
	_, err := buildDeviceAttestArgs(&platformv1.GetDeviceRequest{})
	var argsErr ErrUnexpectedArgsType
	if !errors.As(err, &argsErr) {
		t.Errorf("buildDeviceAttestArgs = %v, want ErrUnexpectedArgsType", err)
	}

	err = decodeDeviceAttestResult(map[string]interface{}{}, &platformv1.GetDeviceResponse{})
	var replyErr ErrUnexpectedReplyType
	if !errors.As(err, &replyErr) {
		t.Errorf("decodeDeviceAttestResult = %v, want ErrUnexpectedReplyType", err)
	}
}
