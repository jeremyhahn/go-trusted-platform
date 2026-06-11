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

package bmc

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// =============================================================================
// Extend fakeBMCClient with EnrollBMC support
// =============================================================================

// enrollBMCClient wraps fakeBMCClient to add EnrollBMC so we don't have to
// modify the shared fake in client_test.go. Embedding covers all other methods.
type enrollBMCClient struct {
	*fakeBMCClient
	enrollResp    *platformv1.BMCEnrollResponse
	enrollErr     error
	lastEnrollReq *platformv1.BMCEnrollRequest
}

func (f *enrollBMCClient) EnrollBMC(ctx context.Context, in *platformv1.BMCEnrollRequest, opts ...grpc.CallOption) (*platformv1.BMCEnrollResponse, error) {
	f.lastEnrollReq = in
	return f.enrollResp, f.enrollErr
}

// goodProtoEnrollResponse returns a minimal proto BMCEnrollResponse for happy-path tests.
func goodProtoEnrollResponse() *platformv1.BMCEnrollResponse {
	now := time.Now()
	return &platformv1.BMCEnrollResponse{
		DeviceId:      42,
		Endpoint:      "10.0.0.1:443",
		Hostname:      "bmc.example.com",
		DnsName:       "bmc.internal.example.com",
		PinSpkiSha256: "sha256/abc123",
		FactoryCertPem: []byte("CERT PEM"),
		FactoryCertMeta: &platformv1.BMCFactoryCertMeta{
			Subject:      "CN=bmc",
			Issuer:       "CN=ca",
			SerialNumber: "deadbeef",
			NotBefore:    timestamppb.New(now.Add(-time.Hour)),
			NotAfter:     timestamppb.New(now.Add(365 * 24 * time.Hour)),
			SpkiSha256:   "aabbcc",
			Sha256:       "ddeeff",
			CapturedAt:   timestamppb.New(now),
		},
		NewCertPem: []byte("NEW CERT"),
		CaCertPem:  []byte("CA CERT"),
		Steps: []*platformv1.BMCEnrollStep{
			{Name: "trust", Ok: true},
			{Name: "factory_cert", Ok: true, Detail: "captured CN=bmc"},
		},
	}
}

// =============================================================================
// Client.EnrollBMC tests
// =============================================================================

func TestSDKEnrollBMC_HappyPath(t *testing.T) {
	protoResp := goodProtoEnrollResponse()
	fc := &enrollBMCClient{
		fakeBMCClient: &fakeBMCClient{},
		enrollResp:    protoResp,
	}
	c := NewClientFromGRPC(fc)

	result, err := c.EnrollBMC(context.Background(), 42, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DeviceID != protoResp.DeviceId {
		t.Errorf("DeviceID: got %d, want %d", result.DeviceID, protoResp.DeviceId)
	}
	if result.Endpoint != protoResp.Endpoint {
		t.Errorf("Endpoint: got %q, want %q", result.Endpoint, protoResp.Endpoint)
	}
	if result.FactoryCertPEM != string(protoResp.FactoryCertPem) {
		t.Errorf("FactoryCertPEM: got %q", result.FactoryCertPEM)
	}
	if result.NewCertPEM != string(protoResp.NewCertPem) {
		t.Errorf("NewCertPEM: got %q", result.NewCertPEM)
	}
	if result.CACertPEM != string(protoResp.CaCertPem) {
		t.Errorf("CACertPEM: got %q", result.CACertPEM)
	}
	if len(result.Steps) != 2 {
		t.Errorf("Steps len: got %d, want 2", len(result.Steps))
	}
	if result.FactoryCertMeta.Subject != "CN=bmc" {
		t.Errorf("FactoryCertMeta.Subject: got %q", result.FactoryCertMeta.Subject)
	}
	// Verify profileID was forwarded
	if fc.lastEnrollReq.ProfileId != 42 {
		t.Errorf("ProfileId: got %d, want 42", fc.lastEnrollReq.ProfileId)
	}
}

func TestSDKEnrollBMC_ErrorWrapped(t *testing.T) {
	fc := &enrollBMCClient{
		fakeBMCClient: &fakeBMCClient{},
		enrollErr:     errors.New("enroll failed"),
	}
	c := NewClientFromGRPC(fc)

	_, err := c.EnrollBMC(context.Background(), 1, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var typed *ErrEnrollFailed
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrEnrollFailed, got %T: %v", err, err)
	}
	if typed.ProfileID != 1 {
		t.Errorf("ProfileID: got %d, want 1", typed.ProfileID)
	}
}

func TestSDKEnrollBMC_OptionsForwarded(t *testing.T) {
	protoResp := goodProtoEnrollResponse()
	fc := &enrollBMCClient{
		fakeBMCClient: &fakeBMCClient{},
		enrollResp:    protoResp,
	}
	c := NewClientFromGRPC(fc)

	tval := true
	fval := false
	opts := &EnrollOptions{
		ReplaceCertificate: &tval,
		RotatePassword:     &fval,
		DNSRegister:        &tval,
		// DANEPublish left nil
	}

	_, err := c.EnrollBMC(context.Background(), 7, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := fc.lastEnrollReq
	if req.ProfileId != 7 {
		t.Errorf("ProfileId: got %d, want 7", req.ProfileId)
	}
	if req.ReplaceCertificate == nil || !*req.ReplaceCertificate {
		t.Error("expected ReplaceCertificate=true to be forwarded")
	}
	if req.RotatePassword == nil || *req.RotatePassword {
		t.Error("expected RotatePassword=false to be forwarded")
	}
	if req.DnsRegister == nil || !*req.DnsRegister {
		t.Error("expected DnsRegister=true to be forwarded")
	}
	if req.DanePublish != nil {
		t.Error("expected DanePublish to remain nil")
	}
}

// =============================================================================
// Converter tests
// =============================================================================

func TestEnrollResultFromProto_NilInput(t *testing.T) {
	result := enrollResultFromProto(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %+v", result)
	}
}

func TestEnrollResultFromProto_FullResponse(t *testing.T) {
	protoResp := goodProtoEnrollResponse()
	result := enrollResultFromProto(protoResp)

	if result.DeviceID != protoResp.DeviceId {
		t.Errorf("DeviceID: got %d, want %d", result.DeviceID, protoResp.DeviceId)
	}
	if result.FactoryCertMeta.Subject != protoResp.FactoryCertMeta.Subject {
		t.Errorf("Subject: got %q, want %q", result.FactoryCertMeta.Subject, protoResp.FactoryCertMeta.Subject)
	}
	if result.FactoryCertMeta.SPKISHA256 != protoResp.FactoryCertMeta.SpkiSha256 {
		t.Errorf("SPKISHA256: got %q, want %q", result.FactoryCertMeta.SPKISHA256, protoResp.FactoryCertMeta.SpkiSha256)
	}
	if result.FactoryCertMeta.NotBefore.IsZero() {
		t.Error("expected non-zero NotBefore")
	}
	if len(result.Steps) != 2 {
		t.Errorf("Steps len: got %d, want 2", len(result.Steps))
	}
	if result.Steps[1].Detail == "" {
		t.Error("expected non-empty Detail for step 1")
	}
}

func TestEnrollOptionsToProto_NilOptions(t *testing.T) {
	req := enrollOptionsToProto(3, nil)
	if req.ProfileId != 3 {
		t.Errorf("ProfileId: got %d, want 3", req.ProfileId)
	}
	if req.ReplaceCertificate != nil {
		t.Error("expected nil ReplaceCertificate")
	}
}

func TestEnrollOptionsToProto_AllSet(t *testing.T) {
	tval := true
	fval := false
	opts := &EnrollOptions{
		ReplaceCertificate: &tval,
		RotatePassword:     &fval,
		DNSRegister:        &tval,
		DANEPublish:        &fval,
	}
	req := enrollOptionsToProto(8, opts)
	if req.ProfileId != 8 {
		t.Errorf("ProfileId: got %d, want 8", req.ProfileId)
	}
	if req.ReplaceCertificate == nil || !*req.ReplaceCertificate {
		t.Error("expected ReplaceCertificate=true")
	}
	if req.RotatePassword == nil || *req.RotatePassword {
		t.Error("expected RotatePassword=false")
	}
	if req.DnsRegister == nil || !*req.DnsRegister {
		t.Error("expected DnsRegister=true")
	}
	if req.DanePublish == nil || *req.DanePublish {
		t.Error("expected DanePublish=false")
	}
}

func TestErrEnrollFailed_Error(t *testing.T) {
	cause := errors.New("grpc error")
	err := &ErrEnrollFailed{ProfileID: 5, Cause: cause}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
	if !errors.Is(err.Unwrap(), cause) {
		t.Error("expected Unwrap to return cause")
	}
}
